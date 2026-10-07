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

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "vmlinux.h"

/* Cgroup allowlist populated by userspace. The build command being traced
 * is run within this.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, __u8);
} target_cgroups SEC(".maps");

/* TGIDs of daemons and their descendants, as seen from witness's PID namespace. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, __u8);
} daemon_tasks SEC(".maps");

/* Identity of witness's own PID namespace. */
const volatile __u64 witness_pidns_ino = 0;

/* Shared ring-buffer payload consumed by ebpf_linux.go. Keep this layout in
 * sync with fileOpenEvent on the Go side.
 */
struct file_open_event {
	__u32 event_type;
	__u32 pid;
	__u32 tid;
	__u32 host_pid;
	__u32 host_tid;
	__u32 host_ppid;
	__u64 cgroup_id;
	__u32 data_len;
	__u32 root_mnt_id;
	__u64 root_ino; // For open events, the task's root ino used to resolve relative paths.
	__s64 error;     // For error events, an error_type, or a negative errno.
	char data[4096]; // For open and cgroup mkdir: Store path, For exec: store <program>\0[argv...]
};

#define EXEC_PART 2048 /* cap on each of exec's filename and argv */
#define EXEC_PART_MAX (EXEC_PART - 1)

enum event_type {
	EVENT_TYPE_OPEN = 1,
	EVENT_TYPE_EXEC = 2,
	EVENT_TYPE_EXIT = 3,
	EVENT_TYPE_ERROR = 4,
	EVENT_TYPE_CGROUP_MKDIR = 5,
	EVENT_TYPE_GROUP_EXIT = 6,
	EVENT_TYPE_OPEN_RAW = 7, // data is the `path` as passed to open(), not resolved
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

/* Count of events lost due to errors with reserving space in the ringbuffer.
 * Such errors cannot be carried through the ringbuffer itself so a side-channel
 * is needed.
 *
 * Userspace asserts this value to be 0 for successful traces.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} ringbuf_drops SEC(".maps");

/* Return PIDs as seen from witness's PID namespace
 * (replaces bpf_get_ns_current_pid_tgid()).
 */
static __always_inline __u32 witness_ns_nr(struct pid *pid) {
	__u32 level = BPF_CORE_READ(pid, level);

	for (__u32 i = 0; i <= 32; i++) {
		if (i > level) {
			break;
		}
		struct pid_namespace *ns = BPF_CORE_READ(pid, numbers[i].ns);
		if (BPF_CORE_READ(ns, ns.inum) == witness_pidns_ino) {
			return BPF_CORE_READ(pid, numbers[i].nr);
		}
	}
	return 0;
}

static __always_inline __u32 witness_ns_tgid(struct task_struct *task) {
	return witness_ns_nr(BPF_CORE_READ(task, group_leader, thread_pid));
}

static __always_inline __u32 witness_ns_tid(struct task_struct *task) {
	return witness_ns_nr(BPF_CORE_READ(task, thread_pid));
}

static __always_inline __u32 current_witness_ns_tgid(void) {
	return witness_ns_tgid((struct task_struct *)bpf_get_current_task());
}

static __always_inline int is_daemon_task(void) {
	__u32 tgid = current_witness_ns_tgid();
	return tgid && bpf_map_lookup_elem(&daemon_tasks, &tgid) != 0;
}

static __always_inline int commandrun_should_trace() {
	__u64 cgroup_id = bpf_get_current_cgroup_id();
	if (bpf_map_lookup_elem(&target_cgroups, &cgroup_id)) {
		return 1;
	}
	
	return is_daemon_task();
}

/* Called during fork/exec to mark child processes and tasks of daemon PIDs. */
static __always_inline void propagate_daemon_task(__u32 parent_tgid, __u32 pid) {
	if (!pid || bpf_map_lookup_elem(&daemon_tasks, &pid)) {
		return;
	}

	if (!bpf_map_lookup_elem(&daemon_tasks, &parent_tgid)) {
		return;
	}

	__u8 enabled = 1;
	bpf_map_update_elem(&daemon_tasks, &pid, &enabled, BPF_ANY);
}

/* Return the current task's TGID/TID as seen from the innermost PID namespace */
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

/* Populates both the namespace-local and host-real PID/TID pairs and host PPID on an
 * event.
 */
static __always_inline void set_event_pids(struct file_open_event *event) {
	__u64 ns_pid_tgid = get_ns_pidtgid();
	event->pid = ns_pid_tgid >> 32;
	event->tid = ns_pid_tgid;

	// Resolve PID/TID relative to witness's pid namespace; 0 if invisible there.
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	event->host_pid = witness_ns_tgid(task);
	event->host_tid = witness_ns_tid(task);

	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	event->host_ppid = parent ? witness_ns_tgid(parent) : 0;
}

/* Reserves and initializes an event. 
 *
 * A full ring buffer is counted in ringbuf_drops and returns NULL.
 */
static __always_inline struct file_open_event *reserve_event(enum event_type type) {
	struct file_open_event *event =
	    bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		__u32 key = 0;
		__u64 *drops = bpf_map_lookup_elem(&ringbuf_drops, &key);
		if (drops) {
			__sync_fetch_and_add(drops, 1);
		}
		return NULL;
	}

	event->event_type = type;
	set_event_pids(event);
	event->cgroup_id = bpf_get_current_cgroup_id();
	event->error = 0;
	event->data_len = 0;

	return event;
}

/* Internal failures are stored as special Error events so that the buffer-draining
 * code can fail the attestor. This ensures that we do not silently swallow errors
 * that might cause the attestor to be incomplete.
 */
static __always_inline void submit_error_event(__s64 error) {
	struct file_open_event *event = reserve_event(EVENT_TYPE_ERROR);
	if (!event) {
		return;
	}

	event->error = error;
	bpf_ringbuf_submit(event, 0);
}

#endif
