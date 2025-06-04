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
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
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
		cr.Command = cmd
		cr.Cmd = cmd // Also set deprecated field for compatibility
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
	// Modern field names (preferred)
	ProgramPath           string                          `json:"programpath,omitempty"`
	PID                   int                             `json:"pid"`
	PPID                  int                             `json:"ppid"`
	ProgramDigest         cryptoutil.DigestSet            `json:"programdigest,omitempty"`
	CommandLine           string                          `json:"commandline,omitempty"`
	ResolvedProgramDigest cryptoutil.DigestSet            `json:"resolvedprogramdigest,omitempty"`
	FilesRead             map[string]cryptoutil.DigestSet `json:"filesread,omitempty"`
	FilesWritten          map[string]cryptoutil.DigestSet `json:"fileswritten,omitempty"`
	
	// Timing information
	StartTime             *time.Time                      `json:"starttime,omitempty"`
	EndTime               *time.Time                      `json:"endtime,omitempty"`
	
	// Network activity
	NetworkActivity       *NetworkActivity                `json:"networkactivity,omitempty"`
	
	// Resource usage
	// NOTE: These performance metrics may be deprecated in a future version as they're
	// not directly relevant for supply chain attestation. Consider if you really need these.
	UserCPUTime           *time.Duration                  `json:"usercputime,omitempty"`
	SystemCPUTime         *time.Duration                  `json:"systemcputime,omitempty"`
	MemoryUsage           uint64                          `json:"memoryusage,omitempty"`      // in bytes
	PeakMemoryUsage       uint64                          `json:"peakmemoryusage,omitempty"` // in bytes
	
	// Deprecated field aliases for backward compatibility
	// These will be populated from the modern fields during unmarshaling
	// and will log warnings when used
	Program          string                          `json:"program,omitempty"`          // Deprecated: Use ProgramPath
	ProcessID        int                             `json:"processid,omitempty"`        // Deprecated: Use PID
	ParentPID        int                             `json:"parentpid,omitempty"`        // Deprecated: Use PPID
	Cmdline          string                          `json:"cmdline,omitempty"`          // Deprecated: Use CommandLine
	ExeDigest        cryptoutil.DigestSet            `json:"exedigest,omitempty"`        // Deprecated: Use ResolvedProgramDigest
	OpenedFiles      map[string]cryptoutil.DigestSet `json:"openedfiles,omitempty"`      // Deprecated: Use FilesRead
	WrittenFiles     map[string]cryptoutil.DigestSet `json:"writtenfiles,omitempty"`     // Deprecated: Use FilesWritten
	CPUTimeUser      *time.Duration                  `json:"cputimeuser,omitempty"`      // Deprecated: Use UserCPUTime
	CPUTimeSystem    *time.Duration                  `json:"cputimesystem,omitempty"`    // Deprecated: Use SystemCPUTime
	MemoryRSS        uint64                          `json:"memoryrss,omitempty"`        // Deprecated: Use MemoryUsage
	PeakMemoryRSS    uint64                          `json:"peakmemoryrss,omitempty"`    // Deprecated: Use PeakMemoryUsage
	
	// Removed deprecated fields
	// Deprecated: Comm is a Linux-specific truncated process name (max 16 chars) from /proc/[pid]/comm.
	// This field is redundant with Program and will be removed in a future version.
	Comm             string                          `json:"-"` // Never marshal/unmarshal
	// Deprecated: Environ exposes potentially sensitive environment variables.
	// Use the dedicated environment attestation instead. This field will be removed in a future version.
	// SECURITY WARNING: This field may contain secrets like API keys and passwords.
	Environ          string                          `json:"-"` // Never marshal/unmarshal
	// Deprecated: SpecBypassIsVuln tracks a specific 2018 CPU vulnerability (Spectre v4).
	// This field will be removed in a future version as it's not relevant for supply chain attestation.
	SpecBypassIsVuln bool                            `json:"-"` // Never marshal/unmarshal
}

// UnmarshalJSON implements custom unmarshaling to handle deprecated fields
func (p *ProcessInfo) UnmarshalJSON(data []byte) error {
	// Use an alias to avoid recursion
	type Alias ProcessInfo
	aux := &struct {
		*Alias
		// Capture deprecated fields during unmarshal
		Comm             string `json:"comm,omitempty"`
		Environ          string `json:"environ,omitempty"`
		SpecBypassIsVuln bool   `json:"specbypassisvuln,omitempty"`
	}{
		Alias: (*Alias)(p),
	}
	
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	
	// Log warnings for deprecated fields that were provided
	deprecatedFieldsUsed := []string{}
	
	if aux.Comm != "" {
		deprecatedFieldsUsed = append(deprecatedFieldsUsed, "comm")
	}
	if aux.Environ != "" {
		deprecatedFieldsUsed = append(deprecatedFieldsUsed, "environ (SECURITY WARNING: may contain secrets)")
	}
	if aux.SpecBypassIsVuln {
		deprecatedFieldsUsed = append(deprecatedFieldsUsed, "specbypassisvuln")
	}
	
	// Check for deprecated field aliases and copy to modern fields
	if p.Program != "" && p.ProgramPath == "" {
		p.ProgramPath = p.Program
		deprecatedFieldsUsed = append(deprecatedFieldsUsed, "program (use programpath)")
	}
	if p.ProcessID != 0 && p.PID == 0 {
		p.PID = p.ProcessID
		deprecatedFieldsUsed = append(deprecatedFieldsUsed, "processid (use pid)")
	}
	if p.ParentPID != 0 && p.PPID == 0 {
		p.PPID = p.ParentPID
		deprecatedFieldsUsed = append(deprecatedFieldsUsed, "parentpid (use ppid)")
	}
	if p.Cmdline != "" && p.CommandLine == "" {
		p.CommandLine = p.Cmdline
		deprecatedFieldsUsed = append(deprecatedFieldsUsed, "cmdline (use commandline)")
	}
	if len(p.ExeDigest) > 0 && len(p.ResolvedProgramDigest) == 0 {
		p.ResolvedProgramDigest = p.ExeDigest
		deprecatedFieldsUsed = append(deprecatedFieldsUsed, "exedigest (use resolvedprogramdigest)")
	}
	if len(p.OpenedFiles) > 0 && len(p.FilesRead) == 0 {
		p.FilesRead = p.OpenedFiles
		deprecatedFieldsUsed = append(deprecatedFieldsUsed, "openedfiles (use filesread)")
	}
	if len(p.WrittenFiles) > 0 && len(p.FilesWritten) == 0 {
		p.FilesWritten = p.WrittenFiles
		deprecatedFieldsUsed = append(deprecatedFieldsUsed, "writtenfiles (use fileswritten)")
	}
	if p.CPUTimeUser != nil && p.UserCPUTime == nil {
		p.UserCPUTime = p.CPUTimeUser
		deprecatedFieldsUsed = append(deprecatedFieldsUsed, "cputimeuser (use usercputime)")
	}
	if p.CPUTimeSystem != nil && p.SystemCPUTime == nil {
		p.SystemCPUTime = p.CPUTimeSystem
		deprecatedFieldsUsed = append(deprecatedFieldsUsed, "cputimesystem (use systemcputime)")
	}
	if p.MemoryRSS != 0 && p.MemoryUsage == 0 {
		p.MemoryUsage = p.MemoryRSS
		deprecatedFieldsUsed = append(deprecatedFieldsUsed, "memoryrss (use memoryusage)")
	}
	if p.PeakMemoryRSS != 0 && p.PeakMemoryUsage == 0 {
		p.PeakMemoryUsage = p.PeakMemoryRSS
		deprecatedFieldsUsed = append(deprecatedFieldsUsed, "peakmemoryrss (use peakmemoryusage)")
	}
	
	if len(deprecatedFieldsUsed) > 0 {
		log.Warnf("ProcessInfo: deprecated fields used: %s", strings.Join(deprecatedFieldsUsed, ", "))
	}
	
	return nil
}

// MarshalJSON implements custom marshaling to populate deprecated fields for compatibility
func (p ProcessInfo) MarshalJSON() ([]byte, error) {
	// Populate deprecated fields from modern fields for backward compatibility
	if p.ProgramPath != "" {
		p.Program = p.ProgramPath
	}
	if p.PID != 0 {
		p.ProcessID = p.PID
	}
	if p.PPID != 0 {
		p.ParentPID = p.PPID
	}
	if p.CommandLine != "" {
		p.Cmdline = p.CommandLine
	}
	if len(p.ResolvedProgramDigest) > 0 {
		p.ExeDigest = p.ResolvedProgramDigest
	}
	if len(p.FilesRead) > 0 {
		p.OpenedFiles = p.FilesRead
	}
	if len(p.FilesWritten) > 0 {
		p.WrittenFiles = p.FilesWritten
	}
	if p.UserCPUTime != nil {
		p.CPUTimeUser = p.UserCPUTime
	}
	if p.SystemCPUTime != nil {
		p.CPUTimeSystem = p.SystemCPUTime
	}
	if p.MemoryUsage != 0 {
		p.MemoryRSS = p.MemoryUsage
	}
	if p.PeakMemoryUsage != 0 {
		p.PeakMemoryRSS = p.PeakMemoryUsage
	}
	
	// Use an alias to avoid recursion
	type Alias ProcessInfo
	return json.Marshal((*Alias)(&p))
}

type CommandRun struct {
	// Modern field names
	Command   []string      `json:"command"`
	Stdout    string        `json:"stdout,omitempty"`
	Stderr    string        `json:"stderr,omitempty"`
	ExitCode  int           `json:"exitcode"`
	
	// Deprecated field aliases
	Cmd       []string      `json:"cmd,omitempty"`       // Deprecated: Use Command
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

// UnmarshalJSON implements custom unmarshaling for CommandRun
func (c *CommandRun) UnmarshalJSON(data []byte) error {
	type Alias CommandRun
	aux := (*Alias)(c)
	
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	
	// Handle deprecated Cmd field
	if len(c.Cmd) > 0 && len(c.Command) == 0 {
		c.Command = c.Cmd
		log.Warn("CommandRun: deprecated field 'cmd' used, please use 'command' instead")
	}
	
	return nil
}

// MarshalJSON implements custom marshaling for CommandRun
func (c CommandRun) MarshalJSON() ([]byte, error) {
	// Populate deprecated field for backward compatibility
	if len(c.Command) > 0 {
		c.Cmd = c.Command
	}
	
	type Alias CommandRun
	return json.Marshal((*Alias)(&c))
}

func (rc *CommandRun) Attest(ctx *attestation.AttestationContext) error {
	if len(rc.Command) == 0 {
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
	c := exec.Command(r.Command[0], r.Command[1:]...)
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
