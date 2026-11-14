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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
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

// TestEBPFTracksDaemonContainer covers --daemons and --track-cgroup with a fake
// container runtime: a daemon started before witness (in its own PID namespace)
// that, when asked by the traced command, creates a cgroup and runs a process
// in it that reads a file.
func TestEBPFTracksDaemonContainer(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Skipf("kernel BTF is unavailable: %v", err)
	}
	if err := unix.Access("/sys/fs/cgroup", unix.W_OK); err != nil {
		t.Skipf("cgroup filesystem is not writable: %v", err)
	}

	tempDir := t.TempDir()
	targetFile := filepath.Join(tempDir, "container-evidence.txt")
	if err := os.WriteFile(targetFile, []byte("read inside the container"), 0o600); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(tempDir, "start.fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := filepath.Join(tempDir, "done")
	cgroupDir := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("witness-test-%d", os.Getpid()))

	// The daemon waits for "start", creates a cgroup, runs a child in it that
	// reads targetFile, then signals done and stays alive.
	daemon := exec.Command("/bin/sh", "-c", `
		read _ <"$1"
		mkdir "$2"
		sh -c 'echo $$ >"$1/cgroup.procs" && exec cat "$2" >/dev/null' sh "$2" "$3"
		touch "$4"
		exec sleep 60
	`, "sh", fifo, cgroupDir, targetFile, done)
	daemon.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWPID}
	if err := daemon.Start(); err != nil {
		t.Fatalf("starting daemon: %v", err)
	}
	t.Cleanup(func() {
		_ = daemon.Process.Kill()
		_ = daemon.Wait()
		_ = os.Remove(cgroupDir)
	})

	cmd := New(
		WithCommand([]string{"/bin/sh", "-c",
			`echo start >"$1"; i=0; while [ ! -e "$2" ] && [ $i -lt 200 ]; do sleep 0.05; i=$((i+1)); done`,
			"sh", fifo, done}),
		WithTracing(true),
		WithTraceBackend(TraceBackendEBPF),
		WithTrackCgroup(true),
		WithDaemonPIDs([]int{daemon.Process.Pid}),
		WithSilent(true),
	)
	ctx, err := attestation.NewContext("test", []attestation.Attestor{cmd})
	if err != nil {
		t.Fatal(err)
	}
	if err := ctx.RunAttestors(); err != nil {
		t.Fatal(err)
	}

	for _, p := range cmd.Processes {
		if _, ok := p.OpenedFiles[targetFile]; !ok {
			continue
		}
		if p.ParentPID != daemon.Process.Pid {
			t.Errorf("parentpid = %d, want the daemon %d", p.ParentPID, daemon.Process.Pid)
		}
		if p.ProcessID == p.HostProcessID {
			t.Errorf("processid and hostprocessid are both %d, want the PID inside the daemon's namespace", p.ProcessID)
		}
		if !strings.HasSuffix(p.CgroupPath, filepath.Base(cgroupDir)) {
			t.Errorf("cgrouppath = %q, want it to end in %q", p.CgroupPath, filepath.Base(cgroupDir))
		}
		return
	}
	t.Fatalf("no traced process recorded opening %q", targetFile)
}
