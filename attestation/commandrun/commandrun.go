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
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/testifysec/go-witness/attestation"
	"github.com/testifysec/go-witness/attestation/environment"
	"github.com/testifysec/go-witness/cryptoutil"
	"github.com/testifysec/go-witness/log"
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
	Cmd                  []string             `json:"cmd"`
	Stdout               string               `json:"stdout,omitempty"`
	Stderr               string               `json:"stderr,omitempty"`
	ExitCode             int                  `json:"exitcode"`
	Processes            []ProcessInfo        `json:"processes,omitempty"`
	Files                map[string]*FileInfo `json:"files,omitempty"`
	Sockets              []SocketInfo         `json:"sockets,omitempty"`
	WitnessPID           int                  `json:"witnesspid"`
	silent               bool
	materials            map[string]cryptoutil.DigestSet
	enableTracing        bool
	environmentBlockList map[string]struct{}
	tetragonAddress      string
	tetragonWatchPrefix  []string
	cleanedup            bool
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
	Access []FileAccess `json:"access"`
}

type FileAccess struct {
	PID        int        `json:"pid"`
	Time       time.Time  `json:"time"`
	HashTime   time.Time  `json:"hashtime,omitempty"`
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

	var tc *TraceContext


	if r.tetragonAddress != "" {
		runtime.LockOSThread()

		c.SysProcAttr = &syscall.SysProcAttr{
			Ptrace: true,
		}

		log.Debugf("Tetragon enabled, connecting to %s", r.tetragonAddress)
		if err := c.Start(); err != nil {
			return err
		}

		tc, err = NewTC(ctx, r, c.Process.Pid)
		if err != nil {
			return err
		}

		err = tc.Start()
		if err != nil {
			return err
		}

		log.Debugf("Proc PID: %d", c.Process.Pid)

		runtime.UnlockOSThread()

		log.Debugf("Tetragon enabled, waiting for %s", r.tetragonAddress)

		syscall.PtraceDetach(c.Process.Pid)
		if err != nil {
			return err
		}

	}

	// if r.enableTracing {
	// 	t, err := r.trace(c, ctx)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	r.Processes = t

	// } else {
	// 	err := c.Wait()
	// 	if exitErr, ok := err.(*exec.ExitError); ok {
	// 		r.ExitCode = exitErr.ExitCode()
	// 	}
	// }

	//check if process is running
	for {
		procStatus, err := getProcStatus(c.Process.Pid)
		if err != nil {
			return err
		}

		log.Debugf("Proc status: %s", procStatus)
		if procStatus == "Z" {
			log.Debugf("Process %d exited", c.Process.Pid)

			//make sure we get all of the exit events
			time.Sleep(time.Millisecond * 100)
			err = tc.Stop(r)
			if err != nil {
				return err
			}
			log.Debugf("Tetragon stopped")

			//wait for all exit events to for dependent processes
			for {
				if r.cleanedup {
					break
				}
			}
			break
		}
		time.Sleep(time.Millisecond * 100)

	}

	if err := c.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			r.ExitCode = exitErr.ExitCode()
		}
	}

	r.Stdout = stdoutBuffer.String()
	r.Stderr = stderrBuffer.String()

	return err
}

func getProcStatus(pid int) (string, error) {
	statusFile := fmt.Sprintf("/proc/%d/status", pid)
	status, err := ioutil.ReadFile(statusFile)
	if err != nil {
		return "", err
	}

	parsedStatus := strings.Split(string(status), "\n")
	for _, line := range parsedStatus {
		if strings.HasPrefix(line, "State:") {
			p := strings.TrimSpace(line[6:])
			q := strings.Split(p, " ")
			return q[0], nil
		}
	}

	return "", fmt.Errorf("state not found in %s", statusFile)
}
