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

// eBPF tracepoints for file and process tracing.
// Args:
//
//	cgroupID:    cgroup for "/sys/fs/cgroup/witness-tracing" used to filter for events of interest.
//	trackCgroup: attach cgroup tracing programs.
//	daemonPIDs:  host PIDs of daemons.
func loadSyscallEBPFTracer(cgroupID uint64, trackCgroup bool, daemonPIDs []int) (*loadedEBPFTracer, error) {
	spec, err := commandrunbpf.LoadFiletraceSyscall()
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}

	var objs commandrunbpf.FiletraceSyscallObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("load objects: %w", err)
	}

	// Default programs
	tracepoints := []struct {
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
	}

	// Cgroup programs
	if trackCgroup {
		tracepoints = append(tracepoints, struct {
			group    string
			name     string
			program  *ebpf.Program
			required bool
		}{"cgroup", "cgroup_mkdir", objs.TraceCgroupMkdir, true})
	}

	links := make([]link.Link, 0, len(tracepoints))
	for _, tp := range tracepoints {
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

	tracer := &loadedEBPFTracer{
		events:        objs.Events,
		targetCgroups: objs.TargetCgroups,
		daemonTasks:   objs.DaemonTasks,
		close: func() error {
			closeLinks(links)
			return objs.Close()
		},
	}
	if err := tracer.addCgroup(cgroupID); err != nil {
		_ = tracer.close()
		return nil, fmt.Errorf("add target cgroup: %w", err)
	}

	for _, pid := range daemonPIDs {
		if err := tracer.addDaemonPID(pid); err != nil {
			_ = tracer.close()
			return nil, fmt.Errorf("add daemon pid %d: %w", pid, err)
		}
	}

	return tracer, nil
}
