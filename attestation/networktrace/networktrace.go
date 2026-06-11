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
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/networktrace/bpf"
	"github.com/in-toto/go-witness/attestation/networktrace/proxy"
	"github.com/in-toto/go-witness/attestation/networktrace/types"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/registry"
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
	attestation.RegisterAttestation(
		Name,
		Type,
		RunType,
		func() attestation.Attestor {
			return New()
		},
		registry.IntConfigOption(
			"proxy-port",
			"Port for the network trace proxy to listen on",
			int(types.DefaultProxyPort),
			func(a attestation.Attestor, val int) (attestation.Attestor, error) {
				nt, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				if val < 1 || val > math.MaxUint16 {
					return a, fmt.Errorf("proxy-port %d out of valid range [1, %d]", val, math.MaxUint16)
				}
				WithProxyPort(uint16(val))(nt)
				return nt, nil
			},
		),
		registry.StringConfigOption(
			"proxy-bind-ipv4",
			"IPv4 address for the proxy to bind to",
			types.DefaultProxyBindIPv4,
			func(a attestation.Attestor, val string) (attestation.Attestor, error) {
				nt, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithProxyBindIPv4(val)(nt)
				return nt, nil
			},
		),
		registry.BoolConfigOption(
			"enable-http-inspection",
			"Enable HTTP/HTTPS traffic inspection via MITM proxy",
			true,
			func(a attestation.Attestor, val bool) (attestation.Attestor, error) {
				nt, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithEnableHTTPInspection(val)(nt)
				return nt, nil
			},
		),
		registry.BoolConfigOption(
			"generate-ca",
			"Auto-generate a CA certificate and key for TLS interception",
			true,
			func(a attestation.Attestor, val bool) (attestation.Attestor, error) {
				nt, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithGenerateCA(val)(nt)
				return nt, nil
			},
		),
		registry.StringConfigOption(
			"ca-cert-path",
			"Path to the CA certificate PEM file for TLS interception",
			types.DefaultCaCertPath,
			func(a attestation.Attestor, val string) (attestation.Attestor, error) {
				nt, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithCACertPath(val)(nt)
				return nt, nil
			},
		),
		registry.StringConfigOption(
			"ca-key-path",
			"Path to the CA key PEM file for TLS interception",
			types.DefaultCaKeyPath,
			func(a attestation.Attestor, val string) (attestation.Attestor, error) {
				nt, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithCAKeyPath(val)(nt)
				return nt, nil
			},
		),
		registry.BoolConfigOption(
			"skip-verify",
			"Skip TLS certificate verification for intercepted connections",
			false,
			func(a attestation.Attestor, val bool) (attestation.Attestor, error) {
				nt, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithSkipVerify(val)(nt)
				return nt, nil
			},
		),
		registry.IntSliceConfigOption(
			"observe-pids",
			"PIDs to observe network activity for",
			nil,
			func(a attestation.Attestor, val []int) (attestation.Attestor, error) {
				nt, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				pids := make([]uint32, 0, len(val))
				for _, pid := range val {
					if pid <= 0 {
						return a, fmt.Errorf("invalid PID %d: must be positive", pid)
					}
					if pid > math.MaxUint32 {
						return a, fmt.Errorf("invalid PID %d: exceeds uint32 range", pid)
					}
					pids = append(pids, uint32(pid))
				}
				WithObservePIDs(pids)(nt)
				return nt, nil
			},
		),
		registry.StringSliceConfigOption(
			"observe-cgroups",
			"Cgroup paths to observe network activity for",
			nil,
			func(a attestation.Attestor, val []string) (attestation.Attestor, error) {
				nt, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithObserveCgroups(val)(nt)
				return nt, nil
			},
		),
		registry.StringSliceConfigOption(
			"observe-commands",
			"Command names to observe network activity for",
			nil,
			func(a attestation.Attestor, val []string) (attestation.Attestor, error) {
				nt, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithObserveCommands(val)(nt)
				return nt, nil
			},
		),
		registry.BoolConfigOption(
			"observe-child-tree",
			"Observe network activity for child processes",
			true,
			func(a attestation.Attestor, val bool) (attestation.Attestor, error) {
				nt, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithObserveChildTree(val)(nt)
				return nt, nil
			},
		),
		registry.BoolConfigOption(
			"record-payload",
			"Record raw payload data in network connections",
			false,
			func(a attestation.Attestor, val bool) (attestation.Attestor, error) {
				nt, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithPayloadRecordPayload(val)(nt)
				return nt, nil
			},
		),
		registry.BoolConfigOption(
			"record-payload-hash",
			"Record SHA256 hash of payload data",
			true,
			func(a attestation.Attestor, val bool) (attestation.Attestor, error) {
				nt, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithPayloadRecordPayloadHash(val)(nt)
				return nt, nil
			},
		),
		registry.Int64ConfigOption(
			"max-payload-size",
			"Maximum size in bytes to store raw payload (0 for unlimited)",
			int64(types.DefaultPayloadConfig().MaxPayloadSize),
			func(a attestation.Attestor, val int64) (attestation.Attestor, error) {
				nt, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				if val < 0 {
					return a, fmt.Errorf("max-payload-size %d must be non-negative", val)
				}
				WithPayloadMaxPayloadSize(val)(nt)
				return nt, nil
			},
		),
	)
}

// NetworkTrace contains the recorded network activity during command execution
type NetworkTrace struct {
	// Timing
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`

	// Network observations
	Connections []types.Connection `json:"connections"`

	// Summary for quick policy evaluation
	Summary types.NetworkSummary `json:"summary"`

	// Configuration used (for reproducibility/auditability)
	Config types.Config `json:"config"`

	// CA certificate used for TLS interception (PEM encoded)
	// Included so verifiers understand what was trusted during attestation
	CACertPEM string `json:"ca_cert_pem,omitempty"`
}

// Attestor implements the network trace attestation
type Attestor struct {
	NetworkTrace NetworkTrace `json:"network_trace"`
	hooks        *attestation.ExecuteHooks
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

func WithProxyPort(port uint16) func(*Attestor) {
	return func(a *Attestor) {
		a.NetworkTrace.Config.ProxyPort = port
	}
}

func WithProxyBindIPv4(addr string) func(*Attestor) {
	return func(a *Attestor) {
		a.NetworkTrace.Config.ProxyBindIPv4 = addr
	}
}

func WithEnableHTTPInspection(enabled bool) func(*Attestor) {
	return func(a *Attestor) {
		a.NetworkTrace.Config.EnableHTTPInspection = enabled
	}
}

func WithGenerateCA(generate bool) func(*Attestor) {
	return func(a *Attestor) {
		a.NetworkTrace.Config.GenerateCA = generate
	}
}

func WithCACertPath(path string) func(*Attestor) {
	return func(a *Attestor) {
		a.NetworkTrace.Config.CACertPath = path
	}
}

func WithCAKeyPath(path string) func(*Attestor) {
	return func(a *Attestor) {
		a.NetworkTrace.Config.CAKeyPath = path
	}
}

func WithSkipVerify(skip bool) func(*Attestor) {
	return func(a *Attestor) {
		a.NetworkTrace.Config.SkipVerify = skip
	}
}

func WithObservePIDs(pids []uint32) func(*Attestor) {
	return func(a *Attestor) {
		a.NetworkTrace.Config.ObservePIDs = pids
	}
}

func WithObserveCgroups(cgroups []string) func(*Attestor) {
	return func(a *Attestor) {
		a.NetworkTrace.Config.ObserveCgroups = cgroups
	}
}

func WithObserveCommands(commands []string) func(*Attestor) {
	return func(a *Attestor) {
		a.NetworkTrace.Config.ObserveCommands = commands
	}
}

func WithObserveChildTree(observe bool) func(*Attestor) {
	return func(a *Attestor) {
		a.NetworkTrace.Config.ObserveChildTree = observe
	}
}

func WithPayloadRecordPayload(record bool) func(*Attestor) {
	return func(a *Attestor) {
		a.NetworkTrace.Config.Payload.RecordPayload = record
	}
}

func WithPayloadRecordPayloadHash(record bool) func(*Attestor) {
	return func(a *Attestor) {
		a.NetworkTrace.Config.Payload.RecordPayloadHash = record
	}
}

func WithPayloadMaxPayloadSize(maxSize int64) func(*Attestor) {
	return func(a *Attestor) {
		a.NetworkTrace.Config.Payload.MaxPayloadSize = maxSize
	}
}

// New creates a new network trace attestor with default configuration
func New() *Attestor {
	return &Attestor{
		NetworkTrace: NetworkTrace{
			Config: types.DefaultConfig(),
		},
	}
}

func NewWithConfig(cfg types.Config) *Attestor {
	return &Attestor{
		NetworkTrace: NetworkTrace{
			Config: cfg,
		},
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
	return jsonschema.Reflect(&NetworkTrace{})
}

func (n *Attestor) IsExperimental() bool {
	return true
}

// proxyRuntime holds the runtime state for proxy coordination
type proxyRuntime struct {
	connChannel    chan types.Connection
	collectorWg    sync.WaitGroup
	shutdownSignal chan struct{}
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
		ProxyPort:  n.NetworkTrace.Config.ProxyPort,
		ProxyIPv4:  n.NetworkTrace.Config.ProxyBindIPv4,
	}

	state, err := bpf.Load(bpfConfig)
	if err != nil {
		log.Errorf("[networktrace] failed to load bpf programs: %v", err)
		return nil, nil, err
	}

	cleanup := func() {
		if err := state.Close(); err != nil {
			log.Errorf("[networktrace] failed to close bpf state: %v", err)
		}
	}

	return state.Maps, cleanup, nil
}

// initProxies creates CA manager and starts the proxy infrastructure
func (n *Attestor) initProxies(ctx *attestation.AttestationContext, bpfMaps *bpf.Maps) (*proxyRuntime, error) {
	runtime := &proxyRuntime{
		connChannel:    make(chan types.Connection, 100),
		shutdownSignal: make(chan struct{}),
		proxyDone:      make(chan struct{}),
	}

	// Start connection collector
	runtime.collectorWg.Go(func() {
		for conn := range runtime.connChannel {
			n.NetworkTrace.Connections = append(n.NetworkTrace.Connections, conn)
		}
	})

	cfg := n.NetworkTrace.Config
	var httpProxy *proxy.HTTPProxy
	if cfg.EnableHTTPInspection {
		cm, err := proxy.NewCAManager(cfg.CAKeyPath, cfg.CACertPath, cfg.GenerateCA)
		if err != nil {
			log.Errorf("[networktrace] failed to create CA manager: %v", err)
			return nil, err
		}
		n.NetworkTrace.CACertPEM = cm.CertPEM()
		httpProxy = proxy.NewHTTPProxy(cm, cfg.Payload, runtime.connChannel, cfg.SkipVerify)
	}

	// Create and start proxy
	tcpProxy := proxy.NewTCPProxy(bpfMaps, httpProxy, cfg.ProxyPort, cfg.ProxyBindIPv4, true, cfg.Payload, runtime.connChannel)

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
	// PreExec: called when command starts, adds PID to BPF filter
	r1, err := n.hooks.RegisterHook(attestation.StagePreExec, Name, func(pid int) error {
		log.Debugf("[networktrace] PreExec hook triggered, tracking PID=%d", pid)
		n.NetworkTrace.Config.ObservePIDs = append(n.NetworkTrace.Config.ObservePIDs, uint32(pid))
		n.NetworkTrace.StartTime = time.Now()
		err := bpfMaps.LoadUserConfig(n.NetworkTrace.Config)
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

	// PreExit: called when command is about to exit (PTRACE_EVENT_EXIT).
	// The process is still frozen by ptrace at this point and it hasn't closed
	// its sockets yet. We must NOT block here, ptrace will only PtraceCont
	// (letting the process actually exit and close sockets) after this hook
	// returns. Blocking on proxy cleanup would deadlock because the proxy's
	// io.Copy is waiting for EOF from the process's socket.
	// Cleanup is still done irrespective of the process exiting
	r2, err := n.hooks.RegisterHook(attestation.StagePreExit, Name, func(pid int) error {
		log.Debugf("[networktrace] PreExit hook triggered, PID=%d", pid)
		n.NetworkTrace.EndTime = time.Now()
		close(runtime.shutdownSignal)
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

	n.NetworkTrace.Summary = types.ComputeSummary(n.NetworkTrace.Connections)
	log.Debugf("[networktrace] attestation complete, collected %d connections", len(n.NetworkTrace.Connections))

	if ctx.Context().Err() != nil {
		return ctx.Context().Err()
	}
	return nil
}
