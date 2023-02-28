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
	"syscall"

	"github.com/testifysec/go-witness/attestation"
	"github.com/testifysec/go-witness/attestation/environment"
	"github.com/testifysec/go-witness/cryptoutil"
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
)

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

func WithEnvironmentBlockList(blockList map[string]struct{}) Option {
	return func(cr *CommandRun) {
		cr.environmentBlockList = blockList
	}
}

func New(opts ...Option) *CommandRun {
	cr := &CommandRun{
		environmentBlockList: environment.DefaultBlockList(),
	}

	for _, opt := range opts {
		opt(cr)
	}

	return cr
}

type ProcessInfo struct {
	Program           string                          `json:"program,omitempty"`
	ProcessID         int                             `json:"processid"`
	ParentPID         int                             `json:"parentpid"`
	ProgramDigest     cryptoutil.DigestSet            `json:"programdigest,omitempty"`
	Comm              string                          `json:"comm,omitempty"`
	Cmdline           string                          `json:"cmdline,omitempty"`
	ExeDigest         cryptoutil.DigestSet            `json:"exedigest,omitempty"`
	OpenedFiles       map[string]cryptoutil.DigestSet `json:"openedfiles,omitempty"`
	Environ           map[string]string               `json:"environ,omitempty"`
	OpenedSockets     []SocketInfo                    `json:"openedsockets,omitempty"`
	OpenedConnections []ConnectionInfo                `json:"openedconnections,omitempty"`
}

type ConnectionInfo struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Bytes    int    `json:"bytes"`
}

type SocketInfo struct {
	Domain   string `json:"domain"`
	Type     string `json:"type"`
	Protocol string `json:"protocol"`
}

type CommandRun struct {
	Cmd       []string      `json:"cmd"`
	Stdout    string        `json:"stdout,omitempty"`
	Stderr    string        `json:"stderr,omitempty"`
	ExitCode  int           `json:"exitcode"`
	Processes []ProcessInfo `json:"processes,omitempty"`

	silent               bool
	materials            map[string]cryptoutil.DigestSet
	enableTracing        bool
	environmentBlockList map[string]struct{}
}

func (rc *CommandRun) Attest(ctx *attestation.AttestationContext) error {
	if len(rc.Cmd) == 0 {
		return attestation.ErrInvalidOption{
			Option: "Cmd",
			Reason: "CommandRun attestation requires a command to run",
		}
	}

	if err := rc.runCmd(ctx); err != nil {
		return err
	}

	return nil
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

func (r *CommandRun) runCmd(ctx *attestation.AttestationContext) error {
	// combine the command and arguments into a single string
	cmd := r.Cmd[0]
	for _, arg := range r.Cmd[1:] {
		cmd += " " + arg
	}

	// Create a new command with the specified command and arguments
	c := exec.Command("/bin/sh", "-c", cmd)

	// Set the command's working directory to the context's working directory
	c.Dir = ctx.WorkingDir()

	// Set up buffers to capture stdout and stderr
	var stdoutBuffer, stderrBuffer bytes.Buffer

	// Set up writers for stdout and stderr
	stdoutWriters := []io.Writer{&stdoutBuffer}
	stderrWriters := []io.Writer{&stderrBuffer}

	// If the command is not silent, write to stdout and stderr as well as the buffers
	if !r.silent {
		stdoutWriters = append(stdoutWriters, os.Stdout)
		stderrWriters = append(stderrWriters, os.Stderr)
	}

	// Create a multi-writer that writes to all of the specified writers
	stdoutWriter := io.MultiWriter(stdoutWriters...)
	stderrWriter := io.MultiWriter(stderrWriters...)

	// Set the command's stdout and stderr to the multi-writers
	c.Stdout = stdoutWriter
	c.Stderr = stderrWriter

	// If tracing is enabled, set the SysProcAttr to enable PTRACE
	if r.enableTracing {
		c.SysProcAttr = &syscall.SysProcAttr{
			Ptrace: true,
		}
	}

	// Set the command's Cloneflags and Uid/GidMappings to sandbox the command in a new user namespace
	c.SysProcAttr.Cloneflags = syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID
	c.SysProcAttr.UidMappings = []syscall.SysProcIDMap{
		{
			ContainerID: os.Geteuid(),
			HostID:      os.Geteuid(),
			Size:        1,
		},
	}
	c.SysProcAttr.GidMappings = []syscall.SysProcIDMap{
		{
			ContainerID: os.Getegid(),
			HostID:      os.Getegid(),
			Size:        1,
		},
	}

	c.SysProcAttr.Credential = &syscall.Credential{
		Uid: uint32(os.Geteuid()),
		Gid: uint32(os.Getegid()),
	}

	var err error

	// Start the command
	if err = c.Start(); err != nil {
		return err
	}

	// If tracing is enabled, trace the command and set the Processes field of the CommandRun struct
	if r.enableTracing {
		r.Processes, err = r.trace(c, ctx)
		if err != nil {
			return err
		}
	} else {
		// Otherwise, wait for the command to complete and set the ExitCode field of the CommandRun struct
		err = c.Wait()
		if exitErr, ok := err.(*exec.ExitError); ok {
			r.ExitCode = exitErr.ExitCode()
		}
	}

	// Set the Stdout and Stderr fields of the CommandRun struct to the captured stdout and stderr, respectively
	r.Stdout = stdoutBuffer.String()
	r.Stderr = stderrBuffer.String()

	// Return any errors that occurred during the execution of the command
	return err
}
