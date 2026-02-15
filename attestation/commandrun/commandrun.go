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
	"fmt"
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
	_ attestation.Attestor            = &CommandRun{}
	_ CommandRunAttestor              = &CommandRun{}
	_ attestation.ExecuteHookDeclarer = &CommandRun{}
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
	Program          string                          `json:"program,omitempty"`
	ProcessID        int                             `json:"processid"`
	ParentPID        int                             `json:"parentpid"`
	ProgramDigest    cryptoutil.DigestSet            `json:"programdigest,omitempty"`
	Comm             string                          `json:"comm,omitempty"`
	Cmdline          string                          `json:"cmdline,omitempty"`
	ExeDigest        cryptoutil.DigestSet            `json:"exedigest,omitempty"`
	OpenedFiles      map[string]cryptoutil.DigestSet `json:"openedfiles,omitempty"`
	Environ          string                          `json:"environ,omitempty"`
	SpecBypassIsVuln bool                            `json:"specbypassisvuln,omitempty"`
}

type CommandRun struct {
	Cmd       []string      `json:"cmd"`
	Stdout    string        `json:"stdout,omitempty"`
	Stderr    string        `json:"stderr,omitempty"`
	ExitCode  int           `json:"exitcode"`
	Processes []ProcessInfo `json:"processes,omitempty"`

	silent        bool
	materials     map[string]cryptoutil.DigestSet
	enableTracing bool
	executeHooks  *attestation.ExecuteHooks
}

func (rc *CommandRun) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&rc)
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

// CommandRun saves the execute hooks using the same mechanism, even though
// it doesn't declare any hooks itself. It is the hook runner. Maybe a hack.
func (rc *CommandRun) DeclareHooks(hooks *attestation.ExecuteHooks) error {
	rc.executeHooks = hooks
	return nil
}

func (rc *CommandRun) runCmd(ctx *attestation.AttestationContext) error {
	c := exec.Command(rc.Cmd[0], rc.Cmd[1:]...)
	c.Dir = ctx.WorkingDir()
	stdoutBuffer := bytes.Buffer{}
	stderrBuffer := bytes.Buffer{}
	stdoutWriters := []io.Writer{&stdoutBuffer}
	stderrWriters := []io.Writer{&stderrBuffer}
	if ctx.OutputWriters() != nil {
		stdoutWriters = append(stdoutWriters, ctx.OutputWriters()...)
		stderrWriters = append(stderrWriters, ctx.OutputWriters()...)
	}

	if !rc.silent {
		stdoutWriters = append(stdoutWriters, os.Stdout)
		stderrWriters = append(stderrWriters, os.Stderr)
	}

	stdoutWriter := io.MultiWriter(stdoutWriters...)
	stderrWriter := io.MultiWriter(stderrWriters...)
	c.Stdout = stdoutWriter
	c.Stderr = stderrWriter

	// Wait for any declared hooks to be registered
	if err := rc.executeHooks.WaitForDeclaredHooks(30 * time.Second); err != nil {
		return fmt.Errorf("failed waiting for hook registration: %w", err)
	}

	// Pre-compute hook flags once to avoid repeated mutex operations
	hasPreExec := rc.executeHooks.HasHooks(attestation.StagePreExec)
	hasPreExit := rc.executeHooks.HasHooks(attestation.StagePreExit)
	needsHookTracing := hasPreExec || hasPreExit

	if rc.enableTracing || needsHookTracing {
		// Locking the thread before enabling tracing and starting the command execution (fork and exec)
		// Only the parent thread that called fork/clone can issue the subsequent tracing commands
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		enableTracing(c)
	}

	if err := c.Start(); err != nil {
		return err
	}

	var err error

	if rc.enableTracing {
		rc.Processes, err = rc.trace(c, ctx, hasPreExec, hasPreExit)
	} else if needsHookTracing {
		err = rc.runWithHooks(c, hasPreExec, hasPreExit)
	} else {
		err = c.Wait()
		if exitErr, ok := err.(*exec.ExitError); ok {
			rc.ExitCode = exitErr.ExitCode()
		}
	}

	rc.Stdout = stdoutBuffer.String()
	rc.Stderr = stderrBuffer.String()
	return err
}
