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
	"syscall"
	"time"

	"github.com/testifysec/go-witness/attestation"
	"github.com/testifysec/go-witness/attestation/environment"
	"github.com/testifysec/go-witness/cryptoutil"
)

const (
	Name    = "command-run"
	Type    = "https://witness.dev/attestations/command-run/v0.2"
	RunType = attestation.Internal
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

func WithTetragon(address string, watchPrefix []string) Option {
	return func(cr *CommandRun) {
		cr.tetragonAddress = address
		cr.tetragonWatchPrefix = watchPrefix
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

type CommandRun struct {
	Cmd                  []string      `json:"cmd"`
	Stdout               string        `json:"stdout,omitempty"`
	Stderr               string        `json:"stderr,omitempty"`
	ExitCode             int           `json:"exitcode"`
	Processes            []ProcessInfo `json:"processes,omitempty"`
	Files                []FileInfo    `json:"files,omitempty"`
	Sockets              []SocketInfo  `json:"sockets,omitempty"`
	WitnessPID           int           `json:"witnesspid"`
	silent               bool
	materials            map[string]cryptoutil.DigestSet
	enableTracing        bool
	environmentBlockList map[string]struct{}
	tetragonAddress      string
	tetragonWatchPrefix  []string
}

type ProcessInfo struct {
	Binary           string               `json:"program,omitempty"`
	Args             string               `json:"args,omitempty"`
	ProcessID        int                  `json:"processid"`
	ParentPID        int                  `json:"parentpid"`
	BinaryDigest     cryptoutil.DigestSet `json:"programdigest,omitempty"`
	StartTime        time.Time            `json:"starttime,omitempty"`
	StopTime         time.Time            `json:"stoptime,omitempty"`
	UID              int                  `json:"uid,omitempty"`
	Environ          string               `json:"environ,omitempty"`
	Flags            string               `json:"flags,omitempty"`
	processEventType EventType
}

type EventType string

const (
	EventTypeExec = "exec"
	EventTypeExit = "exit"
)

type FileInfo struct {
	Path   string       `json:"path"`
	Access []FileAccess `json:"access"`
	PIDs   []int        `json:"pids"`
}

type FileAccess struct {
	ProcessPID int        `json:"pid"`
	Time       time.Time  `json:"time"`
	AccessType AccessType `json:"type"`
	//calculate digest on file open, close or when the calling process is killed
	Digest cryptoutil.DigestSet `json:"digest"`
}

type AccessType string

const (
	AccessTypeRead  AccessType = "read"
	AccessTypeWrite AccessType = "write"
	AccessTypeOpen  AccessType = "open"
	AccessTypeClose AccessType = "close"
)

type SocketAccess struct {
	ProcessPID int        `json:"pid"`
	Time       time.Time  `json:"time"`
	Type       AccessType `json:"type"`
}

type SocketInfo struct {
	RemoteAddress string         `json:"remoteaddress"`
	LocalAddress  string         `json:"address"`
	LocalPort     int            `json:"port"`
	RemotePort    int            `json:"remoteport"`
	SocketType    string         `json:"sockettype"`
	SocketAccess  []SocketAccess `json:"socketaccess"`
}

type SocketType string

const (
	SocketTypeTCP SocketType = "tcp"
	SocketTypeUDP SocketType = "udp"
)

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
	var err error

	r.WitnessPID = os.Getpid()

	c := exec.Command(r.Cmd[0], r.Cmd[1:]...)
	c.Dir = ctx.WorkingDir()
	stdoutBuffer := bytes.Buffer{}
	stderrBuffer := bytes.Buffer{}
	stdoutWriters := []io.Writer{&stdoutBuffer}
	stderrWriters := []io.Writer{&stderrBuffer}
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

	runtime.LockOSThread()

	if err := c.Start(); err != nil {
		return err
	}

	if r.tetragonAddress != "" {
		syscall.Kill(c.Process.Pid, syscall.SIGSTOP)
		tc, err := NewTC(ctx, r, c.Process.Pid)
		if err != nil {
			return err
		}
		err = tc.Start()
		if err != nil {
			return err
		}
		defer tc.Stop(r)
		time.Sleep(time.Second * 1)
		syscall.Kill(c.Process.Pid, syscall.SIGCONT)
	}

	runtime.UnlockOSThread()

	if r.enableTracing {
		t, err := r.trace(c, ctx)
		if err != nil {
			return err
		}
		r.Processes = t

	} else {
		err := c.Wait()
		time.Sleep(time.Second * 1)
		if exitErr, ok := err.(*exec.ExitError); ok {
			r.ExitCode = exitErr.ExitCode()
		}
	}

	r.Stdout = stdoutBuffer.String()
	r.Stderr = stderrBuffer.String()

	return err
}
