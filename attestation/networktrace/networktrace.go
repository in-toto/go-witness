// Copyright 2026 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package networktrace

import (
	"context"
	"sync"
	"time"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/networktrace/bpf"
	"github.com/in-toto/go-witness/attestation/networktrace/proxy"
	"github.com/in-toto/go-witness/attestation/networktrace/types"
	"github.com/in-toto/go-witness/log"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "network-trace"
	Type    = "https://witness.dev/attestations/network-trace/v0.1"
	RunType = attestation.ExecuteRunType
)

var (
	_ attestation.Attestor            = &Attestor{}
	_ attestation.ExecuteHookDeclarer = &Attestor{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

// Attestation contains the recorded network activity during command execution
type Attestation struct {
	// Timing
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`

	// Network observations
	Connections []types.Connection `json:"connections"`

	// Summary for quick policy evaluation
	Summary types.NetworkSummary `json:"summary"`

	// Configuration used (for reproducibility/auditability)
	Config types.Config `json:"config"`
}

// Attestor implements the network trace attestation
type Attestor struct {
	config      types.Config
	attestation Attestation

	hooks *attestation.ExecuteHooks
}

func (n *Attestor) DeclareHooks(hooks *attestation.ExecuteHooks) error {
	err := hooks.Declare(Name, attestation.StagePreExec)
	if err != nil {
		return err
	}
	err = hooks.Declare(Name, attestation.StagePreExit)
	if err != nil {
		return err
	}

	// AttestationContext does not expose hooks through the API,
	// the attestors which declare hooks can store them directly.
	n.hooks = hooks
	return nil
}

// New creates a new network trace attestor with default configuration
func New() *Attestor {
	return &Attestor{
		config: types.DefaultConfig(),
	}
}

func NewWithConfig(config types.Config) *Attestor {
	return &Attestor{
		config: config,
	}
}

func (n *Attestor) Name() string {
	return Name
}

func (n *Attestor) Type() string {
	return Type
}

func (n *Attestor) RunType() attestation.RunType {
	return RunType
}

func (n *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&Attestation{})
}

// proxyRuntime holds the runtime state for proxy coordination
type proxyRuntime struct {
	connChannel    chan types.Connection
	collectorWg    sync.WaitGroup
	shutdownSignal chan struct{}
	cleanupDone    chan struct{}
	proxyDone      chan struct{}
	cancelProxy    context.CancelFunc
}

func (n *Attestor) Attest(ctx *attestation.AttestationContext) error {
	log.Debugf("[networktrace] starting attestation")

	// Initialize BPF programs and maps
	bpfMaps, cleanup, err := n.initBPF()
	if err != nil {
		return err
	}
	defer cleanup()

	// Initialize CA and proxies
	runtime, err := n.initProxies(ctx, bpfMaps)
	if err != nil {
		return err
	}
	defer runtime.cancelProxy()

	// Register execution hooks
	if err := n.registerHooks(bpfMaps, runtime); err != nil {
		return err
	}

	// Wait for shutdown and perform cleanup
	return n.waitAndCleanup(ctx, runtime)
}

// initBPF loads BPF programs and returns maps with a cleanup function
func (n *Attestor) initBPF() (*bpf.Maps, func(), error) {
	bpfConfig := bpf.LoadConfig{
		CgroupPath: "/sys/fs/cgroup", // TODO: allow user to configure
		ProxyPort:  n.config.ProxyPort,
		ProxyIPv4:  n.config.ProxyBindIPv4,
	}

	if err := bpf.Load(bpfConfig); err != nil {
		log.Errorf("[networktrace] failed to load bpf programs: %v", err)
		return nil, nil, err
	}

	bpfMaps, err := bpf.GetMaps()
	if err != nil {
		bpf.Unload(bpfConfig)
		log.Errorf("[networktrace] failed to get bpf maps: %v", err)
		return nil, nil, err
	}

	cleanup := func() {
		bpfMaps.Close()
		if err := bpf.Unload(bpfConfig); err != nil {
			log.Errorf("[networktrace] failed to unload bpf programs: %v", err)
		}
	}

	return bpfMaps, cleanup, nil
}

// initProxies creates CA manager and starts the proxy infrastructure
func (n *Attestor) initProxies(ctx *attestation.AttestationContext, bpfMaps *bpf.Maps) (*proxyRuntime, error) {
	runtime := &proxyRuntime{
		connChannel:    make(chan types.Connection, 100),
		shutdownSignal: make(chan struct{}),
		cleanupDone:    make(chan struct{}),
		proxyDone:      make(chan struct{}),
	}

	// Start connection collector
	runtime.collectorWg.Add(1)
	go func() {
		defer runtime.collectorWg.Done()
		for conn := range runtime.connChannel {
			n.attestation.Connections = append(n.attestation.Connections, conn)
		}
	}()

	// Create and start proxy
	tcpProxy := proxy.NewTCPProxy(bpfMaps, n.config.ProxyPort, n.config.ProxyBindIPv4, true, n.config.Payload, runtime.connChannel)

	var proxyCtx context.Context
	proxyCtx, runtime.cancelProxy = context.WithCancel(ctx.Context())

	// Wait for proxy to be ready before returning
	proxyReady := make(chan struct{})

	go func() {
		if err := tcpProxy.Start(proxyCtx, proxyReady); err != nil {
			log.Errorf("[networktrace] TCP proxy error: %v", err)
		}
		close(runtime.proxyDone)
	}()

	// Wait for proxy to be listening before proceeding
	// This ensures BPF-redirected connections won't fail with "connection refused"
	<-proxyReady

	return runtime, nil
}

// registerHooks sets up PreExec and PreExit hooks for command lifecycle
func (n *Attestor) registerHooks(bpfMaps *bpf.Maps, runtime *proxyRuntime) error {
	if n.config.ObservePIDs == nil {
		n.config.ObservePIDs = make([]uint32, 0)
	}

	// PreExec: called when command starts, adds PID to BPF filter
	r1, err := n.hooks.RegisterHook(attestation.StagePreExec, Name, func(pid int) error {
		log.Debugf("[networktrace] PreExec hook triggered, tracking PID=%d", pid)
		n.config.ObservePIDs = append(n.config.ObservePIDs, uint32(pid))
		n.attestation.StartTime = time.Now()
		n.attestation.Config = n.config
		err := bpfMaps.LoadUserConfig(n.config)
		if err != nil {
			log.Errorf("[networktrace] failed to load user config: %v", err)
		}
		return err
	})
	if err != nil {
		log.Errorf("[networktrace] failed to register pre-exec hook: %v", err)
		return err
	}
	close(r1)

	// PreExit: called when command finishes, signals cleanup
	r2, err := n.hooks.RegisterHook(attestation.StagePreExit, Name, func(pid int) error {
		log.Debugf("[networktrace] PreExit hook triggered, PID=%d", pid)
		n.attestation.EndTime = time.Now()
		close(runtime.shutdownSignal)
		<-runtime.cleanupDone
		return nil
	})
	if err != nil {
		log.Errorf("[networktrace] failed to register pre-exit hook: %v", err)
		return err
	}
	close(r2)

	return nil
}

// waitAndCleanup waits for shutdown signal and performs orderly cleanup
func (n *Attestor) waitAndCleanup(ctx *attestation.AttestationContext, runtime *proxyRuntime) error {
	// Wait for shutdown signal from PreExit hook or context cancellation
	select {
	case <-runtime.shutdownSignal:
	case <-ctx.Context().Done():
	}

	// Cleanup sequence

	// Stop proxy
	runtime.cancelProxy()

	// Wait for proxy to exit
	<-runtime.proxyDone

	// Close connection channel and wait for collector to finish
	close(runtime.connChannel)
	runtime.collectorWg.Wait()

	n.attestation.Summary = types.ComputeSummary(n.attestation.Connections)
	log.Debugf("[networktrace] attestation complete, collected %d connections", len(n.attestation.Connections))

	// Signal that cleanup is done
	close(runtime.cleanupDone)

	if ctx.Context().Err() != nil {
		return ctx.Context().Err()
	}
	return nil
}
