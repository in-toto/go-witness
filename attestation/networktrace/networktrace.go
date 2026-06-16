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
		registry.DurationConfigOption(
			"max-stop-duration",
			"Maximum duration a process may stay frozen waiting for its namespace proxy before the watchdog fails closed",
			types.DefaultMaxStopDuration,
			func(a attestation.Attestor, val time.Duration) (attestation.Attestor, error) {
				nt, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				if val <= 0 {
					return a, fmt.Errorf("max-stop-duration %d must be positive", val)
				}
				WithMaxStopDuration(val)(nt)
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

func WithMaxStopDuration(d time.Duration) func(*Attestor) {
	return func(a *Attestor) {
		a.NetworkTrace.Config.MaxStopDuration = d
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

	bpfMaps     *bpf.Maps
	injector    *proxy.NetnsInjector
	gateWg      sync.WaitGroup
	failOnce    sync.Once
	failClosed  chan struct{} // closed when a fail-closed condition is detected
	failErr     error
	failErrLock sync.Mutex
}

// triggerFailClosed records the first fail-closed cause and signals the
// background loops to stop. The actual teardown (disable gate, drain, clear
// maps) is performed by failClosedTeardown.
func (r *proxyRuntime) triggerFailClosed(cause error) {
	r.failOnce.Do(func() {
		r.failErrLock.Lock()
		r.failErr = cause
		r.failErrLock.Unlock()
		close(r.failClosed)
	})
}

func (r *proxyRuntime) failClosedCause() error {
	r.failErrLock.Lock()
	defer r.failErrLock.Unlock()
	return r.failErr
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

	// Keep the proxy infrastructure down until the SIGCONT path
	// (gate-sweep + watchdog) are provably running. This guarantees no process can be frozen
	// before there is something able to resume it.
	if err := state.Maps.SetTracingDisabled(true); err != nil {
		log.Errorf("[networktrace] failed to disable tracing: %v", err)
		_ = state.Close()
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
		bpfMaps:        bpfMaps,
		failClosed:     make(chan struct{}),
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

	// Current namespace proxy is ready
	if err := bpfMaps.SetProxyReady(bpfMaps.HostNetnsInum); err != nil {
		log.Errorf("[networktrace] failed to mark witness netns proxy ready: %v", err)
		runtime.cancelProxy()
		return nil, fmt.Errorf("mark witness netns proxy ready: %w", err)
	}

	runtime.injector = proxy.NewNetnsInjector(tcpProxy, cfg.ProxyPort)
	n.startGateLoops(proxyCtx, runtime)

	return runtime, nil
}

// startGateLoops launches the gate-sweep loop and the watchdog. The sweep is
// the normal SIGCONT path; the watchdog is a fault detector that fails closed
// if it ever has to resume a process the sweep should have handled.
func (n *Attestor) startGateLoops(ctx context.Context, runtime *proxyRuntime) {
	maxStop := n.NetworkTrace.Config.MaxStopDuration
	if maxStop <= 0 {
		maxStop = types.DefaultMaxStopDuration
	}
	const sweepInterval = 5 * time.Millisecond

	// Gate-sweep loop: discover namespaces with frozen tasks, inject a proxy
	// for each, mark it ready, then drain+SIGCONT every task in that namespace.
	runtime.gateWg.Go(func() {
		ticker := time.NewTicker(sweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-runtime.failClosed:
				return
			case <-ticker.C:
				n.sweepGate(ctx, runtime)
			}
		}
	})

	// Watchdog: any task frozen longer than maxStop is a fault.
	runtime.gateWg.Go(func() {
		ticker := time.NewTicker(maxStop / 2)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-runtime.failClosed:
				return
			case <-ticker.C:
				n.checkWatchdog(runtime, maxStop)
			}
		}
	})
}

// sweepGate sets up proxies for any namespace that has frozen tasks awaiting
// one, then wakes those tasks. The ordering (inject -> SetProxyReady -> drain)
// preserves the publish-before-recheck barrier with the eBPF gate.
func (n *Attestor) sweepGate(ctx context.Context, runtime *proxyRuntime) {
	tasks, err := runtime.bpfMaps.SnapshotGate()
	if err != nil {
		log.Errorf("[networktrace] gate snapshot failed: %v", err)
		return
	}
	if len(tasks) == 0 {
		return
	}

	// distinct namespaces that still need a proxy.
	pending := make(map[uint32]struct{})
	for _, t := range tasks {
		if !runtime.bpfMaps.IsProxyReady(t.NetnsInum) {
			pending[t.NetnsInum] = struct{}{}
		}
	}

	for netns := range pending {
		if err := runtime.injector.Inject(ctx, netns); err != nil {
			// Injection failure is unrecoverable: fail closed. The teardown
			// drains and wakes every frozen task, so nothing is stranded.
			// As an attestor, can't silently ignore recording failures
			log.Errorf("[networktrace] proxy injection failed for netns %d: %v", netns, err)
			runtime.triggerFailClosed(fmt.Errorf("proxy injection failed for netns %d: %w", netns, err))
			return
		}
		// Flip readiness BEFORE draining (publish-before-recheck barrier).
		if err := runtime.bpfMaps.SetProxyReady(netns); err != nil {
			log.Errorf("[networktrace] mark proxy ready failed for netns %d: %v", netns, err)
			runtime.triggerFailClosed(fmt.Errorf("mark proxy ready for netns %d: %w", netns, err))
			return
		}
		if err := runtime.bpfMaps.DrainGate(netns, func(t bpf.FrozenTask) error {
			return bpf.SendSIGCONT(t.HostTID)
		}); err != nil {
			log.Errorf("[networktrace] drain/SIGCONT failed for netns %d: %v", netns, err)
		}
	}
}

// checkWatchdog resumes (and fails closed on) any task that has been frozen
// longer than maxStop. In healthy operation this never fires.
func (n *Attestor) checkWatchdog(runtime *proxyRuntime, maxStop time.Duration) {
	tasks, err := runtime.bpfMaps.SnapshotGate()
	if err != nil {
		log.Errorf("[networktrace] watchdog snapshot failed: %v", err)
		return
	}
	nowBoot, err := bpf.GetMonotonicNs()
	if err != nil {
		log.Errorf("[networktrace] watchdog clock read failed: %v", err)
		return
	}
	for _, t := range tasks {
		if t.StopTsNs == 0 || nowBoot <= t.StopTsNs {
			continue
		}
		age := time.Duration(nowBoot-t.StopTsNs) * time.Nanosecond
		if age <= maxStop {
			continue
		}
		// Fault: unstick the process so it is never stranded, then fail closed.
		log.Errorf("[networktrace] WATCHDOG: task host_tid=%d netns=%d frozen for %s (> %s); resuming and failing closed",
			t.HostTID, t.NetnsInum, age, maxStop)
		_ = bpf.SendSIGCONT(t.HostTID)
		runtime.triggerFailClosed(fmt.Errorf("watchdog: task %d frozen longer than %s", t.HostTID, maxStop))
		return
	}
}

// failClosedTeardown disables the gate, drains+wakes every frozen task across
// all namespaces, and empties the interception maps so the proxy drains to zero
// and exits. It never leaves a process frozen.
func (n *Attestor) failClosedTeardown(runtime *proxyRuntime) {
	m := runtime.bpfMaps
	if m == nil {
		return
	}
	// 1. Stop issuing new SIGSTOPs.
	if err := m.SetTracingDisabled(true); err != nil {
		log.Errorf("[networktrace] fail-closed: disable gate: %v", err)
	}
	// 2. Wake everyone (global drain).
	if err := m.DrainGate(0, func(t bpf.FrozenTask) error {
		return bpf.SendSIGCONT(t.HostTID)
	}); err != nil {
		log.Errorf("[networktrace] fail-closed: drain gate: %v", err)
	}
	// 3. Empty interception maps so the proxy stops redirecting and exits.
	if err := m.ClearInterceptionMaps(); err != nil {
		log.Errorf("[networktrace] fail-closed: clear maps: %v", err)
	}
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
			n.failClosedTeardown(runtime)
			runtime.triggerFailClosed(fmt.Errorf("pre-exec setup failed: %w", err))
			return err
		}
		// Enable tracing after config is loaded and proxy is ready
		if err := bpfMaps.SetTracingDisabled(false); err != nil {
			log.Errorf("[networktrace] failed to enable tracing: %v", err)
			n.failClosedTeardown(runtime)
			runtime.triggerFailClosed(fmt.Errorf("enable tracing failed: %w", err))
			return err
		}
		return nil
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
	// Wait for shutdown signal from PreExit hook, a fail-closed condition, or
	// context cancellation.
	select {
	case <-runtime.shutdownSignal:
	case <-runtime.failClosed:
		log.Errorf("[networktrace] failing closed: %v", runtime.failClosedCause())
		n.failClosedTeardown(runtime)
	case <-ctx.Context().Done():
	}

	// Cleanup sequence

	runtime.cancelProxy()
	runtime.gateWg.Wait()
	if runtime.injector != nil {
		runtime.injector.Close()
	}

	// Wait for proxy to exit
	<-runtime.proxyDone

	// Close connection channel and wait for collector to finish
	close(runtime.connChannel)
	runtime.collectorWg.Wait()

	n.NetworkTrace.Summary = types.ComputeSummary(n.NetworkTrace.Connections)
	log.Debugf("[networktrace] attestation complete, collected %d connections", len(n.NetworkTrace.Connections))

	if cause := runtime.failClosedCause(); cause != nil {
		return cause
	}

	if ctx.Context().Err() != nil {
		return ctx.Context().Err()
	}
	return nil
}
