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

//go:build linux

package bpf

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/in-toto/go-witness/attestation/networktrace/types"
)

func loadLifecycleTestState(t *testing.T) *State {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root privileges")
	}
	state, err := Load(LoadConfig{
		CgroupPath: "/sys/fs/cgroup",
		ProxyPort:  28777,
		ProxyIPv4:  "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("load BPF lifecycle programs: %v", err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.Maps.SetTracingDisabled(true); err != nil {
		t.Fatal(err)
	}
	return state
}

func waitLifecycleTerminal(t *testing.T, maps *Maps) LifecycleState {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		state, err := maps.ReadLifecycleState()
		if err != nil {
			t.Fatal(err)
		}
		if state.Status == LifecycleExited || state.Status == LifecycleFailed {
			return state
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for terminal lifecycle state")
	return LifecycleState{}
}

func TestTrackedTreeFinalExitDisablesAdmission(t *testing.T) {
	state := loadLifecycleTestState(t)
	if err := state.Maps.LoadUserConfig(types.Config{ObserveCommands: []string{"nc"}}); err != nil {
		t.Fatal(err)
	}

	root := exec.Command("sleep", "0.3")
	if err := root.Start(); err != nil {
		t.Fatal(err)
	}
	if err := state.Maps.StartProcessTree(uint32(root.Process.Pid)); err != nil {
		_ = root.Process.Kill()
		t.Fatal(err)
	}

	// An unrelated process exit must not change the exact tree count.
	if err := exec.Command("true").Run(); err != nil {
		t.Fatal(err)
	}
	mid, err := state.Maps.ReadLifecycleState()
	if err != nil {
		t.Fatal(err)
	}
	if mid.LiveTasks != 1 || mid.Status != LifecycleRunning {
		t.Fatalf("mid-run lifecycle = %+v, want one running task", mid)
	}

	if err := root.Wait(); err != nil {
		t.Fatal(err)
	}
	terminal := waitLifecycleTerminal(t, state.Maps)
	if terminal.Status != LifecycleExited || terminal.LiveTasks != 0 || !terminal.TracingDisabled || terminal.TerminalTsNs == 0 {
		t.Fatalf("terminal lifecycle = %+v", terminal)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan string, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			received <- ""
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		data, _ := io.ReadAll(conn)
		received <- string(data)
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	client := exec.Command("sh", "-c", fmt.Sprintf("printf POST_EXIT | nc -q 0 127.0.0.1 %d", port))
	if out, err := client.CombinedOutput(); err != nil {
		t.Fatalf("post-exit direct connection failed: %v: %s", err, out)
	}
	select {
	case got := <-received:
		if got != "POST_EXIT" {
			t.Fatalf("server received %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("post-exit connection was redirected or stopped")
	}
	gates, err := state.Maps.SnapshotGate()
	if err != nil {
		t.Fatal(err)
	}
	if len(gates) != 0 {
		t.Fatalf("gate entries remain after terminal exit: %+v", gates)
	}
}

func TestLifecycleCounterUnderflowFailsClosed(t *testing.T) {
	state := loadLifecycleTestState(t)
	root := exec.Command("sleep", "0.2")
	if err := root.Start(); err != nil {
		t.Fatal(err)
	}
	if err := state.Maps.StartProcessTree(uint32(root.Process.Pid)); err != nil {
		_ = root.Process.Kill()
		t.Fatal(err)
	}

	var key uint32
	corrupt := task_trackerControlVal{LifecycleStatus: uint64(LifecycleRunning)}
	if err := state.Maps.ControlMap.Put(&key, &corrupt); err != nil {
		t.Fatal(err)
	}
	if err := root.Wait(); err != nil {
		t.Fatal(err)
	}
	terminal := waitLifecycleTerminal(t, state.Maps)
	if terminal.Status != LifecycleFailed || terminal.Error != LifecycleErrorCounterUnderflow || !terminal.TracingDisabled {
		t.Fatalf("underflow lifecycle = %+v", terminal)
	}
}
