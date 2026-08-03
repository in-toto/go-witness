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

/* TGID/PID allowlist */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, __u8);
} daemon_tasks SEC(".maps");

/* Shared ring-buffer payload consumed by ebpf_linux.go. Keep this layout in
 * sync with fileOpenEvent on the Go side.
 */
struct file_open_event {
	__u32 event_type;
	__u32 pid;
	__u32 tid;
	__s32 dfd;
	__s64 error;
	__u32 host_pid;
	__u32 host_tid;
	__u64 cgroup_id;
	char path[4096];
	char mount_dev[4096];
	char mount_type[4096];
	char mount_data[4096];
	__u64 mount_flags;
};

enum event_type {
	EVENT_TYPE_OPEN = 1,
	EVENT_TYPE_EXEC = 2,
	EVENT_TYPE_EXIT = 3,
	EVENT_TYPE_ERROR = 4,
	EVENT_TYPE_CGROUP_MKDIR = 5,
	EVENT_TYPE_MOUNT = 6,
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

static __always_inline int commandrun_should_trace() {
	__u64 cgroup_id = bpf_get_current_cgroup_id();
	if (bpf_map_lookup_elem(&target_cgroups, &cgroup_id)) {
		return 1;
	}

	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	return bpf_map_lookup_elem(&daemon_tasks, &tgid) != 0;
}

/* Called during exec to mark child processes and tasks of daemon PIDs.
 */
static __always_inline void propagate_daemon_tasks(void) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;

	if (bpf_map_lookup_elem(&daemon_tasks, &tgid)) {
		return;
	}

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	if (!parent) {
		return;
	}
	__u32 parent_tgid = BPF_CORE_READ(parent, tgid);

	if (!bpf_map_lookup_elem(&daemon_tasks, &parent_tgid)) {
		return;
	}

	__u8 enabled = 1;
	bpf_map_update_elem(&daemon_tasks, &tgid, &enabled, BPF_ANY);
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

/* Populates both the namespace-local and host-real pid/tid pairs on an
 * event. Used for /proc/<pid>/... paths that require host-pids.
 */
static __always_inline void set_event_pids(struct file_open_event *event) {
	__u64 ns_pid_tgid = get_ns_pidtgid();
	__u64 host_pid_tgid = bpf_get_current_pid_tgid();

	event->pid = ns_pid_tgid >> 32;
	event->tid = ns_pid_tgid;
	event->host_pid = host_pid_tgid >> 32;
	event->host_tid = host_pid_tgid;
}

/* Best-effort read of a mount string argument, any of which may be NULL
 * (e.g. data is commonly NULL, and some filesystems don't need a source).
 */
static __always_inline void read_user_str_or_empty(char *dst, __u32 size, const char *src) {
	if (!src) {
		dst[0] = '\0';
		return;
	}
	if (bpf_probe_read_user_str(dst, size, src) < 0) {
		dst[0] = '\0';
	}
}

/* Internal failures are stored as special Error events so that the buffer-draining
 * code can fail the attestor. This ensures that we do not silently swallow errors
 * that might cause the attestor to be incomplete.
 */
static __always_inline void submit_error_event(__s64 error) {
	if (!commandrun_should_trace()) {
		return;
	}

	struct file_open_event *event =
	    bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return;
	}

	event->event_type = EVENT_TYPE_ERROR;
	set_event_pids(event);
	event->cgroup_id = bpf_get_current_cgroup_id();
	event->dfd = 0;
	event->error = error;
	event->path[0] = '\0';
	bpf_ringbuf_submit(event, 0);
}

#endif
