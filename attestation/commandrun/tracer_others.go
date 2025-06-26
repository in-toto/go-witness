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

//go:build !linux

package commandrun

import (
	"fmt"
	"os/exec"
	"runtime"
	"time"

	"github.com/in-toto/go-witness/attestation"
)

// stubTracer is a placeholder implementation for non-Linux platforms
type stubTracer struct {
	cmd          *exec.Cmd
	ctx          *attestation.AttestationContext
	opts         TracerOptions
	mainExitCode int
	startTime    *time.Time
	endTime      *time.Time
}

func newPlatformTracer(ctx *attestation.AttestationContext, opts TracerOptions) Tracer {
	return &stubTracer{
		ctx:  ctx,
		opts: opts,
	}
}

func (t *stubTracer) Start(cmd *exec.Cmd) error {
	t.cmd = cmd
	now := time.Now()
	t.startTime = &now
	return cmd.Start()
}

func (t *stubTracer) Wait() error {
	err := t.cmd.Wait()
	now := time.Now()
	t.endTime = &now
	if exitErr, ok := err.(*exec.ExitError); ok {
		t.mainExitCode = exitErr.ExitCode()
	}
	return err
}

func (t *stubTracer) GetProcessTree() []ProcessInfo {
	// Return minimal process info for the main process only
	// This is a stub - full implementation will come later
	processInfo := ProcessInfo{
		ProcessID: t.cmd.Process.Pid,
		Program:   t.cmd.Path,
		Cmdline:   fmt.Sprintf("%v", t.cmd.Args),
	}
	
	// Add warning about missing tracing support
	if t.opts.EnableHashing || t.opts.EnableNetworkTrace {
		// This warning will be captured in logs
		fmt.Fprintf(t.cmd.Stderr, "Warning: Process tracing is not yet implemented on %s\n", runtime.GOOS)
	}
	
	return []ProcessInfo{processInfo}
}

func (t *stubTracer) GetStartTime() *time.Time {
	return t.startTime
}

func (t *stubTracer) GetEndTime() *time.Time {
	return t.endTime
}