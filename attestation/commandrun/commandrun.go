// Copyright 2021 The Witness Contributors
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

package commandrun

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "command-run"
	Type    = "https://witness.dev/attestations/command-run/v0.1"
	RunType = attestation.ExecuteRunType
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor      = &CommandRun{}
	_ CommandRunAttestor        = &CommandRun{}
	_ attestation.MultiExporter = &CommandRun{}
)

type CommandRunAttestor interface {
	// Attestor
	Name() string
	Type() string
	RunType() attestation.RunType
	Attest(ctx *attestation.AttestationContext) error
	Data() *CommandRun
}

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type Option func(*CommandRun)

func WithCommand(cmd []string) Option {
	return func(cr *CommandRun) {
		cr.Cmd = cmd
	}
}

func WithMaterials(materials map[string]cryptoutil.DigestSet) Option {
	return func(cr *CommandRun) {
		cr.materials = materials
	}
}

func WithTracing(enabled bool) Option {
	return func(cr *CommandRun) {
		cr.enableTracing = enabled
	}
}

func WithSilent(silent bool) Option {
	return func(cr *CommandRun) {
		cr.silent = silent
	}
}

func WithTracerOptions(opts TracerOptions) Option {
	return func(cr *CommandRun) {
		cr.tracerOptions = opts
	}
}

func New(opts ...Option) *CommandRun {
	cr := &CommandRun{}

	for _, opt := range opts {
		opt(cr)
	}

	return cr
}

// NetworkActivity represents network operations performed by a process.
// This is an optional feature controlled by TracerOptions.EnableNetworkTrace.
type NetworkActivity struct {
	// Sockets created by the process
	Sockets []SocketInfo `json:"sockets,omitempty"`
	
	// Connections made or accepted
	Connections []ConnectionInfo `json:"connections,omitempty"`
	
	// Data transfer summary
	BytesSent     uint64 `json:"bytessent,omitempty"`
	BytesReceived uint64 `json:"bytesreceived,omitempty"`
}

// SocketInfo represents a network socket created by a process
type SocketInfo struct {
	Domain   string     `json:"domain"`   // AF_INET, AF_INET6, AF_UNIX, etc.
	Type     string     `json:"type"`     // SOCK_STREAM, SOCK_DGRAM, etc.
	Protocol string     `json:"protocol"` // tcp, udp, etc.
	Created  *time.Time `json:"created,omitempty"`
}

// ConnectionInfo represents a network connection
type ConnectionInfo struct {
	Type         string     `json:"type"`         // "connect", "bind", "listen", "accept"
	LocalAddr    string     `json:"localaddr,omitempty"`
	RemoteAddr   string     `json:"remoteaddr,omitempty"`
	Timestamp    *time.Time `json:"timestamp,omitempty"`
	Success      bool       `json:"success"`
	ErrorMessage string     `json:"errormessage,omitempty"`
}

// ProcessInfo contains information about a single process in the process tree
type ProcessInfo struct {
	Program          string                          `json:"program,omitempty"`
	ProcessID        int                             `json:"processid"`
	ParentPID        int                             `json:"parentpid"`
	ProgramDigest    cryptoutil.DigestSet            `json:"programdigest,omitempty"`
	// Deprecated: Comm is a Linux-specific truncated process name (max 16 chars) from /proc/[pid]/comm.
	// This field is redundant with Program and will be removed in a future version.
	Comm             string                          `json:"comm,omitempty"`
	Cmdline          string                          `json:"cmdline,omitempty"`
	ExeDigest        cryptoutil.DigestSet            `json:"exedigest,omitempty"`
	OpenedFiles      map[string]cryptoutil.DigestSet `json:"openedfiles,omitempty"`
	// Deprecated: Environ exposes potentially sensitive environment variables.
	// Use the dedicated environment attestation instead. This field will be removed in a future version.
	// SECURITY WARNING: This field may contain secrets like API keys and passwords.
	Environ          string                          `json:"environ,omitempty"`
	// Deprecated: SpecBypassIsVuln tracks a specific 2018 CPU vulnerability (Spectre v4).
	// This field will be removed in a future version as it's not relevant for supply chain attestation.
	SpecBypassIsVuln bool                            `json:"specbypassisvuln,omitempty"`
	
	// New fields for enhanced tracing
	
	// Timing information
	StartTime        *time.Time                      `json:"starttime,omitempty"`
	EndTime          *time.Time                      `json:"endtime,omitempty"`
	
	// File write operations (path -> digest after write)
	WrittenFiles     map[string]cryptoutil.DigestSet `json:"writtenfiles,omitempty"`
	
	// Network activity
	NetworkActivity  *NetworkActivity                `json:"networkactivity,omitempty"`
	
	// Resource usage
	// NOTE: These performance metrics may be deprecated in a future version as they're
	// not directly relevant for supply chain attestation. Consider if you really need these.
	CPUTimeUser      *time.Duration                 `json:"cputimeuser,omitempty"`
	CPUTimeSystem    *time.Duration                 `json:"cputimesystem,omitempty"`
	MemoryRSS        uint64                         `json:"memoryrss,omitempty"`      // in bytes
	PeakMemoryRSS    uint64                         `json:"peakmemoryrss,omitempty"` // in bytes
}

type CommandRun struct {
	Cmd       []string      `json:"cmd"`
	Stdout    string        `json:"stdout,omitempty"`
	Stderr    string        `json:"stderr,omitempty"`
	ExitCode  int           `json:"exitcode"`
	Processes []ProcessInfo `json:"processes,omitempty"` // Deprecated: Use ExportedAttestations() to get trace data

	silent         bool
	materials      map[string]cryptoutil.DigestSet
	enableTracing  bool
	tracerOptions  TracerOptions
	processTree    []ProcessInfo // Internal storage for MultiExporter
	entryPointPID  int
	startTime      *time.Time    // Overall execution start time
	endTime        *time.Time    // Overall execution end time
}

func (a *CommandRun) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&a)
}

func (rc *CommandRun) Attest(ctx *attestation.AttestationContext) error {
	if len(rc.Cmd) == 0 {
		return attestation.ErrAttestor{
			Name:    rc.Name(),
			RunType: rc.RunType(),
			Reason:  "CommandRun attestation requires a command to run",
		}
	}

	if err := rc.runCmd(ctx); err != nil {
		return err
	}

	return nil
}

func (rc *CommandRun) Data() *CommandRun {
	return rc
}

func (rc *CommandRun) Name() string {
	return Name
}

func (rc *CommandRun) Type() string {
	return Type
}

func (rc *CommandRun) RunType() attestation.RunType {
	return RunType
}

func (rc *CommandRun) TracingEnabled() bool {
	return rc.enableTracing
}

// ExportedAttestations implements the MultiExporter interface
func (rc *CommandRun) ExportedAttestations() []attestation.Attestor {
	if !rc.enableTracing || len(rc.processTree) == 0 {
		return nil
	}

	traceAttestation := &TraceAttestation{
		Processes:      rc.processTree,
		EntryPoint:     rc.entryPointPID,
		TracingOptions: rc.tracerOptions,
		Platform:       runtime.GOOS,
		StartTime:      rc.startTime,
		EndTime:        rc.endTime,
	}

	// Return both the trace attestation (for backward compatibility)
	// and the runtime-trace format (for spec compliance)
	runtimeTrace := NewRuntimeTraceCollector(traceAttestation)
	return []attestation.Attestor{traceAttestation, runtimeTrace}
}

func (r *CommandRun) runCmd(ctx *attestation.AttestationContext) error {
	c := exec.Command(r.Cmd[0], r.Cmd[1:]...)
	c.Dir = ctx.WorkingDir()
	stdoutBuffer := bytes.Buffer{}
	stderrBuffer := bytes.Buffer{}
	stdoutWriters := []io.Writer{&stdoutBuffer}
	stderrWriters := []io.Writer{&stderrBuffer}
	if ctx.OutputWriters() != nil {
		stdoutWriters = append(stdoutWriters, ctx.OutputWriters()...)
		stderrWriters = append(stderrWriters, ctx.OutputWriters()...)
	}

	if !r.silent {
		stdoutWriters = append(stdoutWriters, os.Stdout)
		stderrWriters = append(stderrWriters, os.Stderr)
	}

	stdoutWriter := io.MultiWriter(stdoutWriters...)
	stderrWriter := io.MultiWriter(stderrWriters...)
	c.Stdout = stdoutWriter
	c.Stderr = stderrWriter

	var err error
	if r.enableTracing {
		// Use new tracer architecture
		tracer := NewTracer(ctx, r.tracerOptions)
		
		if err := tracer.Start(c); err != nil {
			return err
		}
		
		err = tracer.Wait()
		r.processTree = tracer.GetProcessTree()
		r.startTime = tracer.GetStartTime()
		r.endTime = tracer.GetEndTime()
		
		// Store entry point PID
		if c.Process != nil {
			r.entryPointPID = c.Process.Pid
		}
		
		// For backward compatibility, also populate Processes field
		r.Processes = r.processTree
		
		if exitErr, ok := err.(*exec.ExitError); ok {
			r.ExitCode = exitErr.ExitCode()
		}
	} else {
		// Non-tracing path
		if err := c.Start(); err != nil {
			return err
		}
		
		err = c.Wait()
		if exitErr, ok := err.(*exec.ExitError); ok {
			r.ExitCode = exitErr.ExitCode()
		}
	}

	r.Stdout = stdoutBuffer.String()
	r.Stderr = stderrBuffer.String()
	return err
}
