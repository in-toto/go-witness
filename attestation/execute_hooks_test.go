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

package attestation

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestExecuteHooksStageCompletesOnce(t *testing.T) {
	var hooks ExecuteHooks
	if err := hooks.Declare("observer", StagePreExec); err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	ready, err := hooks.RegisterHook(StagePreExec, "observer", func(pid int) error {
		if pid != 42 {
			t.Fatalf("hook PID = %d, want 42", pid)
		}
		calls.Add(1)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	close(ready)

	if err := hooks.RunHooks(StagePreExec, 42); err != nil {
		t.Fatal(err)
	}
	<-hooks.StageDone(StagePreExec)
	if err := hooks.StageError(StagePreExec); err != nil {
		t.Fatalf("stage error = %v", err)
	}
	if err := hooks.RunHooks(StagePreExec, 99); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("hook calls = %d, want 1", got)
	}
}

func TestExecuteHooksStageAbortBroadcasts(t *testing.T) {
	var hooks ExecuteHooks
	if err := hooks.Declare("observer", StagePreExec); err != nil {
		t.Fatal(err)
	}

	var called atomic.Bool
	ready, err := hooks.RegisterHook(StagePreExec, "observer", func(int) error {
		called.Store(true)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	close(ready)

	done := hooks.StageDone(StagePreExec)
	var waiters sync.WaitGroup
	waiters.Add(2)
	for range 2 {
		go func() {
			defer waiters.Done()
			<-done
		}()
	}

	want := errors.New("command did not start")
	hooks.AbortStage(StagePreExec, want)
	waiters.Wait()

	if got := hooks.StageError(StagePreExec); !errors.Is(got, want) {
		t.Fatalf("stage error = %v, want %v", got, want)
	}
	if err := hooks.RunHooks(StagePreExec, 42); err != nil {
		t.Fatalf("repeated RunHooks error = %v, want nil", err)
	}
	if called.Load() {
		t.Fatal("aborted stage invoked its callback")
	}

	other := errors.New("later error")
	hooks.AbortStage(StagePreExec, other)
	if got := hooks.StageError(StagePreExec); !errors.Is(got, want) {
		t.Fatalf("first stage result was overwritten: %v", got)
	}
}
