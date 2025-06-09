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
	_ attestation.Attestor = &CommandRun{}
	_ CommandRunAttestor   = &CommandRun{}
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

func New(opts ...Option) *CommandRun {
	cr := &CommandRun{}

	for _, opt := range opts {
		opt(cr)
	}

	return cr
}

type ProcessInfo struct {
	Program          string                          `json:"program,omitempty" jsonschema:"title=Program Path,description=Path to the executed program"`
	ProcessID        int                             `json:"processid" jsonschema:"title=Process ID,description=Process identifier"`
	ParentPID        int                             `json:"parentpid" jsonschema:"title=Parent Process ID,description=Parent process identifier"`
	ProgramDigest    cryptoutil.DigestSet            `json:"programdigest,omitempty" jsonschema:"title=Program Digest,description=Cryptographic digest of the program binary"`
	Comm             string                          `json:"comm,omitempty" jsonschema:"title=Command Name,description=Command name from /proc/[pid]/comm"`
	Cmdline          string                          `json:"cmdline,omitempty" jsonschema:"title=Command Line,description=Full command line from /proc/[pid]/cmdline"`
	ExeDigest        cryptoutil.DigestSet            `json:"exedigest,omitempty" jsonschema:"title=Executable Digest,description=Cryptographic digest of the executable"`
	OpenedFiles      map[string]cryptoutil.DigestSet `json:"openedfiles,omitempty" jsonschema:"title=Opened Files,description=Files opened during execution with their digests"`
	Environ          string                          `json:"environ,omitempty" jsonschema:"title=Environment,description=Process environment variables"`
	SpecBypassIsVuln bool                            `json:"specbypassisvuln,omitempty" jsonschema:"title=Speculative Bypass Vulnerability,description=Whether CPU is vulnerable to speculative execution attacks"`
}

type CommandRun struct {
	Cmd       []string      `json:"cmd" jsonschema:"title=Command,description=Command and arguments to execute"`
	Stdout    string        `json:"stdout,omitempty" jsonschema:"title=Standard Output,description=Captured stdout from the command"`
	Stderr    string        `json:"stderr,omitempty" jsonschema:"title=Standard Error,description=Captured stderr from the command"`
	ExitCode  int           `json:"exitcode" jsonschema:"title=Exit Code,description=Command exit code"`
	Processes []ProcessInfo `json:"processes,omitempty" jsonschema:"title=Process Information,description=Detailed process execution information when tracing is enabled"`

	silent        bool
	materials     map[string]cryptoutil.DigestSet
	enableTracing bool
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

func (rc *CommandRun) Documentation() attestation.Documentation {
	return attestation.Documentation{
		Summary: "Records command execution details including exit code, stdout/stderr, and optional process tracing",
		Usage: []string{
			"Capture build command output and exit status",
			"Trace system calls and file access during command execution",
			"Record command execution for compliance and auditing",
		},
		Example: "witness run -s compile -k key.pem -- make build",
	}
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
	if r.enableTracing {
		enableTracing(c)
	}

	if err := c.Start(); err != nil {
		return err
	}

	var err error
	if r.enableTracing {
		r.Processes, err = r.trace(c, ctx)
	} else {
		err = c.Wait()
		if exitErr, ok := err.(*exec.ExitError); ok {
			r.ExitCode = exitErr.ExitCode()
		}
	}

	r.Stdout = stdoutBuffer.String()
	r.Stderr = stderrBuffer.String()
	return err
}
