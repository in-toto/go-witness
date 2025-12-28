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

//go:build linux

package commandrun

import (
	"testing"

	"github.com/in-toto/go-witness/attestation"
	"github.com/invopop/jsonschema"
)

// mockHookAttestor is a test attestor that implements ExecuteHookDeclarer
// to verify that hooks are called correctly during command execution.
type mockHookAttestor struct {
	name       string
	hooks      *attestation.ExecuteHooks
	preExec    bool
	preExit    bool
	preExecPID int
	preExitPID int
}

func (m *mockHookAttestor) Name() string {
	return m.name
}

func (m *mockHookAttestor) Type() string {
	return "https://witness.dev/attestations/mock-hook/v0.1"
}

func (m *mockHookAttestor) RunType() attestation.RunType {
	return attestation.ExecuteRunType
}

func (m *mockHookAttestor) Attest(ctx *attestation.AttestationContext) error {
	// Register hooks based on configuration
	if m.preExec {
		ready, err := m.hooks.RegisterHook(attestation.StagePreExec, m.name, func(pid int) error {
			m.preExecPID = pid
			return nil
		})
		if err != nil {
			return err
		}
		close(ready)
	}

	if m.preExit {
		ready, err := m.hooks.RegisterHook(attestation.StagePreExit, m.name, func(pid int) error {
			m.preExitPID = pid
			return nil
		})
		if err != nil {
			return err
		}
		close(ready)
	}

	return nil
}

func (m *mockHookAttestor) DeclareHooks(hooks *attestation.ExecuteHooks) error {
	m.hooks = hooks
	if m.preExec {
		if err := hooks.Declare(m.name, attestation.StagePreExec); err != nil {
			return err
		}
	}
	if m.preExit {
		if err := hooks.Declare(m.name, attestation.StagePreExit); err != nil {
			return err
		}
	}
	return nil
}

func (m *mockHookAttestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&m)
}

const (
	status = `
Name:   blkcg_punt_bio
Umask:  0000
State:  I (idle)
Tgid:   214
Ngid:   0
Pid:    214
PPid:   2
TracerPid:      0
Uid:    0       0       0       0
Gid:    0       0       0       0
FDSize: 64
Groups:
NStgid: 214
NSpid:  214
NSpgid: 0
NSsid:  0
Threads:        1
SigQ:   0/514646
SigPnd: 0000000000000000
ShdPnd: 0000000000000000
SigBlk: 0000000000000000
SigIgn: ffffffffffffffff
SigCgt: 0000000000000000
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
NoNewPrivs:     0
Seccomp:        0
Speculation_Store_Bypass:       thread vulnerable
Cpus_allowed:   ffffffff
Cpus_allowed_list:      0-31
Mems_allowed:   00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000001
Mems_allowed_list:      0
voluntary_ctxt_switches:        2
nonvoluntary_ctxt_switches:     0
	`
)

func Test_getPPIDFromStatus(t *testing.T) {
	byteStatus := []byte(status)

	ppid, err := getPPIDFromStatus(byteStatus)
	if err != nil {
		t.Errorf("getPPIDFromStatus() error = %v", err)
		return
	}

	if ppid != 2 {
		t.Errorf("getPPIDFromStatus() = %v, want %v", ppid, 2)
	}

}

func Test_getSpecBypassIsVulnFromStatus(t *testing.T) {
	byteStatus := []byte(status)

	isVuln := getSpecBypassIsVulnFromStatus(byteStatus)

	if isVuln != true {
		t.Errorf("getSpecBypassIsVulnFromStatus() = %v, want %v", isVuln, true)
	}

}

func Test_preExecHook(t *testing.T) {
	mock := &mockHookAttestor{
		name:    "test-preexec",
		preExec: true,
	}

	cmd := New(
		WithCommand([]string{"go", "version"}),
		WithSilent(true),
	)

	ctx, err := attestation.NewContext("test", []attestation.Attestor{cmd, mock})
	if err != nil {
		t.Fatalf("failed to create attestation context: %v", err)
	}

	if err := ctx.RunAttestors(); err != nil {
		t.Fatalf("failed to run attestors: %v", err)
	}

	if mock.preExecPID == 0 {
		t.Error("preExec hook was not called (PID is 0)")
	}
}

func Test_preExitHook(t *testing.T) {
	mock := &mockHookAttestor{
		name:    "test-preexit",
		preExit: true,
	}

	cmd := New(
		WithCommand([]string{"go", "version"}),
		WithSilent(true),
	)

	ctx, err := attestation.NewContext("test", []attestation.Attestor{cmd, mock})
	if err != nil {
		t.Fatalf("failed to create attestation context: %v", err)
	}

	if err := ctx.RunAttestors(); err != nil {
		t.Fatalf("failed to run attestors: %v", err)
	}

	if mock.preExitPID == 0 {
		t.Error("preExit hook was not called (PID is 0)")
	}
}

func Test_preExecAndPreExitHooks(t *testing.T) {
	mock := &mockHookAttestor{
		name:    "test-both-hooks",
		preExec: true,
		preExit: true,
	}

	cmd := New(
		WithCommand([]string{"go", "version"}),
		WithSilent(true),
	)

	ctx, err := attestation.NewContext("test", []attestation.Attestor{cmd, mock})
	if err != nil {
		t.Fatalf("failed to create attestation context: %v", err)
	}

	if err := ctx.RunAttestors(); err != nil {
		t.Fatalf("failed to run attestors: %v", err)
	}

	if mock.preExecPID == 0 {
		t.Error("preExec hook was not called (PID is 0)")
	}

	if mock.preExitPID == 0 {
		t.Error("preExit hook was not called (PID is 0)")
	}

	if mock.preExecPID != mock.preExitPID {
		t.Errorf("preExec PID (%d) does not match preExit PID (%d)", mock.preExecPID, mock.preExitPID)
	}
}

func Test_preExecHookWithTracing(t *testing.T) {
	mock := &mockHookAttestor{
		name:    "test-preexec-tracing",
		preExec: true,
	}

	cmd := New(
		WithCommand([]string{"go", "version"}),
		WithSilent(true),
		WithTracing(true),
	)

	ctx, err := attestation.NewContext("test", []attestation.Attestor{cmd, mock})
	if err != nil {
		t.Fatalf("failed to create attestation context: %v", err)
	}

	if err := ctx.RunAttestors(); err != nil {
		t.Fatalf("failed to run attestors: %v", err)
	}

	if mock.preExecPID == 0 {
		t.Error("preExec hook was not called (PID is 0)")
	}

	if len(cmd.Processes) == 0 {
		t.Error("tracing was enabled but no processes were recorded")
	}
}
