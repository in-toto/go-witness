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

#ifndef WITNESS_COMMANDRUN_FILETRACE_COMMON_H
#define WITNESS_COMMANDRUN_FILETRACE_COMMON_H

/* Set by Go before load. Every program uses it to ignore processes outside the
 * command-run cgroup, which keeps witness' own file activity out of the output.
 */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "vmlinux.h"
volatile const __u64 target_cgroup_id = 0;

/* Shared ring-buffer payload consumed by ebpf_linux.go. Keep this layout in
 * sync with fileOpenEvent on the Go side.
 */
struct file_open_event {
	__u32 event_type;
	__u32 pid;
	__u32 tid;
	__s32 dfd;
	__s64 error;
	char path[256];
};

enum event_type {
	EVENT_TYPE_OPEN = 1,
	EVENT_TYPE_EXEC = 2,
	EVENT_TYPE_EXIT = 3,
	EVENT_TYPE_ERROR = 4,
};

enum error_type {
	ERROR_TYPE_PENDING_OPEN_UPDATE = 1,
	ERROR_TYPE_PENDING_OPEN_MISSING = 2,
};

struct sched_process_exit_args {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	char comm[16];
	__s32 pid;
	__s32 prio;
};

/* Ring buffer that store open, exec, and exit events captured by tracepoints. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 29);
} events SEC(".maps");

static __always_inline int commandrun_in_target_cgroup() {
	if (target_cgroup_id == 0) {
		return 0;
	}
	return bpf_get_current_cgroup_id() == target_cgroup_id;
}

/* Return the current task's TGID/TID as seen from its innermost PID namespace,
 * packed in the same format as bpf_get_current_pid_tgid().
 *
 * Needed for when witness is running in a container to avoid reporting host-POV PIDs.
 */
static __always_inline __u64 get_ns_pidtgid(void) {
	struct task_struct *task =
	    (struct task_struct *)bpf_get_current_task();
	struct task_struct *leader = BPF_CORE_READ(task, group_leader);
	struct pid *tgid_pid = BPF_CORE_READ(leader, thread_pid);
	struct pid *tid_pid = BPF_CORE_READ(task, thread_pid);
	__u32 tgid_level = BPF_CORE_READ(tgid_pid, level);
	__u32 tid_level = BPF_CORE_READ(tid_pid, level);

	if (tgid_level > 32 || tid_level > 32) {
		return 0;
	}

	__u32 tgid = BPF_CORE_READ(tgid_pid, numbers[tgid_level].nr);
	__u32 tid = BPF_CORE_READ(tid_pid, numbers[tid_level].nr);
	return ((__u64)tgid << 32) | tid;
}

/* Internal failures are stored as special Error events so that the buffer-draining
 * code can fail the attestor. This ensures that we do not silently swallow errors
 * that might cause the attestor to be incomplete.
 */
static __always_inline void submit_error_event(__s64 error) {
	if (!commandrun_in_target_cgroup()) {
		return;
	}

	struct file_open_event *event =
	    bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return;
	}

	__u64 pid_tgid = get_ns_pidtgid();
	event->event_type = EVENT_TYPE_ERROR;
	event->pid = pid_tgid >> 32;
	event->tid = pid_tgid;
	event->dfd = 0;
	event->error = error;
	event->path[0] = '\0';
	bpf_ringbuf_submit(event, 0);
}

#endif
