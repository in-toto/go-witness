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
	"fmt"
	"sync"
	"time"
)

// ExecuteHooks are tied to the commandrun attestor and provide a way to
// tap into the lifecycle of processes it spawns.

// ExecuteHookStage represents different points in the process lifecycle
// where attestors can hook in.
type ExecuteHookStage int

const (
	// StagePreExec is called after fork but before exec continues.
	// The process is frozen and no user code has run yet using PTRACE after receiving SIGTRAP.
	// Use this to set up monitoring (BPF maps, seccomp, etc.)
	StagePreExec ExecuteHookStage = iota

	// StagePreExit is called when the process is about to exit but
	// hasn't completed yet. Relies on PTRACE_EVENT_EXIT.
	// Use this to stop monitoring and ensure clean capture.
	StagePreExit
)

func (s ExecuteHookStage) String() string {
	switch s {
	case StagePreExec:
		return "PreExec"
	case StagePreExit:
		return "PreExit"
	default:
		return "Unknown"
	}
}

// ExecuteHookDeclaration represents the intent to register a hook
type ExecuteHookDeclaration struct {
	Attestor string
	Stage    ExecuteHookStage
}

// ExecuteHooks provides extension points for attestors that need to
// interact with processes spawned by command-run.
//
// This is intentionally command-run centric. Command-run is the only
// attestor that executes processes; other attestors observe or modify
// those processes and need coordination with command-run's lifecycle.
type ExecuteHooks struct {
	mu sync.Mutex
	// declarationToFulfilled tracks which declared hooks have been registered
	declarationToFulfilled map[ExecuteHookDeclaration]bool
	hooks                  []registeredHook

	allFulfilled chan struct{}
	closedOnce   sync.Once
}

type registeredHook struct {
	attestor string
	stage    ExecuteHookStage
	// fn is called with the PID of the traced process. This signature may be expanded
	// to support other use cases.
	fn    func(pid int) error
	ready chan struct{}
}

func (h *ExecuteHooks) Declare(attestor string, stage ExecuteHookStage) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.declarationToFulfilled == nil {
		h.declarationToFulfilled = make(map[ExecuteHookDeclaration]bool)
		h.allFulfilled = make(chan struct{})
	}

	// Declaration can only be made once - multiple declarations doesn't mean multiple hooks.
	// Right now there is no use case where multiple hooks per attestor per stage are needed.
	if _, exists := h.declarationToFulfilled[ExecuteHookDeclaration{attestor, stage}]; exists {
		return fmt.Errorf("hook for attestor %q at stage %s already declared", attestor, stage)
	}

	decl := ExecuteHookDeclaration{attestor, stage}
	h.declarationToFulfilled[decl] = false
	return nil
}

// RegisterHook registers a function to be called at the specified stage
// of process execution. The returned channel must be closed by the caller
// once their setup is complete and they're ready to receive the callback.4
// At this stage all the hooks would already have been declared.
//
// Example:
//
//	ready := ctx.ExecuteHooks().RegisterHook(StagePreExec, "network-trace", func(pid int) error {
//	    return bpfMaps.AddTrackedPID(uint32(pid))
//	})
//	// ... complete setup ...
//	close(ready)  // Signal ready to receive callback
func (h *ExecuteHooks) RegisterHook(stage ExecuteHookStage, name string, fn func(pid int) error) (chan<- struct{}, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	decl := ExecuteHookDeclaration{Attestor: name, Stage: stage}
	if _, declared := h.declarationToFulfilled[decl]; !declared {
		return nil, fmt.Errorf("hook for attestor %q at stage %s not declared", name, stage)
	} else if h.declarationToFulfilled[decl] {
		return nil, fmt.Errorf("hook for attestor %q at stage %s already registered", name, stage)
	}

	ready := make(chan struct{})
	h.hooks = append(h.hooks, registeredHook{
		attestor: name,
		stage:    stage,
		fn:       fn,
		ready:    ready,
	})

	h.declarationToFulfilled[decl] = true

	if h.checkAllFulfilled() {
		h.closedOnce.Do(func() {
			close(h.allFulfilled)
		})
	}

	return ready, nil
}

func (h *ExecuteHooks) checkAllFulfilled() bool {
	for _, fulfilled := range h.declarationToFulfilled {
		if !fulfilled {
			return false
		}
	}
	return true
}

func (h *ExecuteHooks) WaitForDeclaredHooks(timeout time.Duration) error {
	h.mu.Lock()
	if len(h.declarationToFulfilled) == 0 {
		h.mu.Unlock()
		return nil // Nothing declared, nothing to wait for
	}
	ch := h.allFulfilled
	h.mu.Unlock()

	select {
	case <-ch:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("timeout waiting for hook registration: %v", h.unfulfilled())
	}
}

func (h *ExecuteHooks) unfulfilled() []ExecuteHookDeclaration {
	h.mu.Lock()
	defer h.mu.Unlock()

	var result []ExecuteHookDeclaration
	for decl, fulfilled := range h.declarationToFulfilled {
		if !fulfilled {
			result = append(result, decl)
		}
	}
	return result
}

// RunHooks waits for all registered hooks of the given stage to signal
// readiness, then calls each hook with the given PID. Returns on first error.
//
// This should be called by command-run at the appropriate lifecycle points.
func (h *ExecuteHooks) RunHooks(stage ExecuteHookStage, pid int) error {
	h.mu.Lock()
	var stageHooks []registeredHook
	for _, hook := range h.hooks {
		if hook.stage == stage {
			stageHooks = append(stageHooks, hook)
		}
	}
	h.mu.Unlock()

	if len(stageHooks) == 0 {
		return nil
	}

	// Wait for all hooks of this stage to signal readiness
	for _, hook := range stageHooks {
		<-hook.ready
	}

	// Run all hooks
	for _, hook := range stageHooks {
		if err := hook.fn(pid); err != nil {
			return fmt.Errorf("hook %q at stage %s failed: %w", hook.attestor, stage, err)
		}
	}

	return nil
}

// HasHooks returns true if any hooks are registered for the given stage.
func (h *ExecuteHooks) HasHooks(stage ExecuteHookStage) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, hook := range h.hooks {
		if hook.stage == stage {
			return true
		}
	}
	return false
}
