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

//go:build linux && ebpf_integration

package commandrun

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/in-toto/go-witness/attestation"
	"golang.org/x/sys/unix"
)

func TestEBPFTracksChildProcess(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Skipf("kernel BTF is unavailable: %v", err)
	}
	if err := unix.Access("/sys/fs/cgroup", unix.W_OK); err != nil {
		t.Skipf("cgroup filesystem is not writable: %v", err)
	}

	catPath, err := exec.LookPath("cat")
	if err != nil {
		t.Skipf("cat is unavailable: %v", err)
	}
	wcPath, err := exec.LookPath("wc")
	if err != nil {
		t.Skipf("wc is unavailable: %v", err)
	}

	tempDir := t.TempDir()
	file1 := filepath.Join(tempDir, "cat-input.txt")
	file2 := filepath.Join(tempDir, "wc-input.txt")
	for path, contents := range map[string][]byte{
		file1: []byte("read by cat"),
		file2: []byte("read by wc"),
	} {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cmd := New(
		WithCommand([]string{
			"/bin/sh", "-c",
			`"$1" "$3" >/dev/null & "$2" -c "$4" >/dev/null & wait`,
			"sh", catPath, wcPath, file1, file2,
		}),
		WithTracing(true),
		WithTraceBackend(TraceBackendEBPF),
		WithSilent(true),
	)

	ctx, err := attestation.NewContext("test", []attestation.Attestor{cmd})
	if err != nil {
		t.Fatal(err)
	}
	if err := ctx.RunAttestors(); err != nil {
		t.Fatal(err)
	}

	expected := map[string]string{
		filepath.Base(catPath): file1,
		filepath.Base(wcPath):  file2,
	}
	observed := make(map[string]ProcessInfo)
	for _, process := range cmd.Processes {
		openedFiles := make([]string, 0, len(process.OpenedFiles))
		for path := range process.OpenedFiles {
			openedFiles = append(openedFiles, path)
		}
		slices.Sort(openedFiles)
		t.Logf("recorded process: pid=%d comm=%q program=%q opened_files=%q",
			process.ProcessID, process.Comm, process.Program, openedFiles)

		requiredFile, ok := expected[process.Comm]
		if !ok {
			continue
		}
		if _, ok := process.OpenedFiles[requiredFile]; ok {
			observed[process.Comm] = process
		}
	}

	for comm, requiredFile := range expected {
		process, ok := observed[comm]
		if !ok {
			t.Errorf("process %q did not record opened file %q", comm, requiredFile)
			continue
		}

		for otherComm, otherFile := range expected {
			if otherComm == comm {
				continue
			}
			if _, ok := process.OpenedFiles[otherFile]; ok {
				t.Errorf("process %q unexpectedly recorded %q opened by %q", comm, otherFile, otherComm)
			}
		}
	}

	catProcess, catOK := observed[filepath.Base(catPath)]
	wcProcess, wcOK := observed[filepath.Base(wcPath)]
	if catOK && wcOK && catProcess.ProcessID == wcProcess.ProcessID {
		t.Errorf("cat and wc files were recorded under the same process ID %d", catProcess.ProcessID)
	}
}
