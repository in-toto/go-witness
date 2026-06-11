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

package commandrun

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	commandrunbpf "github.com/in-toto/go-witness/attestation/commandrun/bpf"
)

// File tracing for command-run using syscall tracepoints. Tracepoints are attached to both
// sys_entry and sys_exit for open* and exec/exit which emit these events through a shared
// ring buffer.
// open* are used for tracking OpenedFiles, exec/exit to track lifecycle events.
//
// Args:
//
//	cgroupID:	cgroup for "/sys/fs/cgroup/witness-tracing" used to filter for events of interest.
func loadSyscallEBPFTracer(cgroupID uint64) (*loadedEBPFTracer, error) {
	spec, err := commandrunbpf.LoadFiletraceSyscall()
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}
	if err := spec.Variables["target_cgroup_id"].Set(cgroupID); err != nil {
		return nil, fmt.Errorf("set target cgroup id: %w", err)
	}

	var objs commandrunbpf.FiletraceSyscallObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("load objects: %w", err)
	}

	links := make([]link.Link, 0, 8)
	for _, tp := range []struct {
		group    string
		name     string
		program  *ebpf.Program
		required bool
	}{
		{"syscalls", "sys_enter_open", objs.TraceOpen, false},
		{"syscalls", "sys_enter_openat", objs.TraceOpenat, true},
		{"syscalls", "sys_enter_openat2", objs.TraceOpenat2, false},
		{"syscalls", "sys_exit_open", objs.TraceOpenExit, false},
		{"syscalls", "sys_exit_openat", objs.TraceOpenatExit, true},
		{"syscalls", "sys_exit_openat2", objs.TraceOpenat2Exit, false},
		{"sched", "sched_process_exec", objs.TraceSchedProcessExec, true},
		{"sched", "sched_process_exit", objs.TraceSchedProcessExit, true},
	} {
		l, err := link.Tracepoint(tp.group, tp.name, tp.program, nil)
		if err != nil {
			if !tp.required && errors.Is(err, os.ErrNotExist) {
				continue
			}
			closeLinks(links)
			objs.Close()
			return nil, fmt.Errorf("attach %s/%s: %w", tp.group, tp.name, err)
		}
		links = append(links, l)
	}

	return &loadedEBPFTracer{
		events: objs.Events,
		close: func() error {
			closeLinks(links)
			return objs.Close()
		},
	}, nil
}
