//go:build ignore

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

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "filetrace_common.h"

#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Pending opens are used to retain state between sys_entry and sys_exit
// tracepoint functions.
//
// State retention between these functions is only required to ensure failed
// path reads at sys_enter can be retried on sys_exit.
//
// Path reads might fail at sys_enter if the pointer hasn't yet been mapped
// outside of the userspace context.
struct pending_open {
	__u64 filename;
	__s32 dfd;
	__s64 error;
	__u8 truncated;
	char path[256];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192 * 12);
	__type(key, __u64);
	__type(value, struct pending_open);
} pending_opens SEC(".maps");

// Called on sys_enter for open* paths.
// - Try reading the path.
// - Store pending_open to be decoded upon sys_exit
static __always_inline int save_open_event(const char *filename, __s32 dfd) {
	if (!commandrun_should_trace()) {
		return 0;
	}

	// Keyed by the host (real) pid/tgid, not the namespace-local one.
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pending_open pending = {
	    .filename = (__u64)filename,
	    .dfd = dfd,
	    .error = 0,
	};

	// Try to read the path buffer as a string on sys_enter for open.
	// If this fails (or is truncated) the pending_open event is marked as such so that it can
	// be retried at sys_exit.
	long copied = bpf_probe_read_user_str(pending.path,
					      sizeof(pending.path), filename);
	if (copied < 0) {
		pending.error = copied;
		pending.path[0] = '\0';
	} else if (copied == (long)sizeof(pending.path)) {
		// If the buffer is filled exactly to the size of buffer the
		// string may be truncated.
		pending.truncated = 1;
	}

	long update_ret =
	    bpf_map_update_elem(&pending_opens, &pid_tgid, &pending, BPF_ANY);
	if (update_ret < 0) {
		submit_error_event(ERROR_TYPE_PENDING_OPEN_UPDATE);
	}
	return 0;
}

// Called on sys_exit for open* syscalls.
// - If pending_open has an error, trying re-reading the path buffer.
// - Upon success or failure, dispatch an event to the ring buffer to be decoded
// outside of eBPF in go.
static __always_inline int submit_pending_open_event(__s64 ret) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	// Do not submit failed opens, but remove the state saved on sys_enter.
	if (ret < 0) {
		bpf_map_delete_elem(&pending_opens, &pid_tgid);
		return 0;
	}

	struct pending_open *pending =
	    bpf_map_lookup_elem(&pending_opens, &pid_tgid);
	if (!pending) {
		submit_error_event(ERROR_TYPE_PENDING_OPEN_MISSING);
		return 0;
	}

	if (!commandrun_should_trace()) {
		bpf_map_delete_elem(&pending_opens, &pid_tgid);
		return 0;
	}

	struct file_open_event *event =
	    bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		bpf_map_delete_elem(&pending_opens, &pid_tgid);
		return 0;
	}

	event->event_type = EVENT_TYPE_OPEN;
	set_event_pids(event);
	event->cgroup_id = bpf_get_current_cgroup_id();
	event->dfd = pending->dfd;
	event->error = pending->error;

	// If reading the path failed at sys_enter, try that again here.
	// If this fails as well, return an error event.
	if (pending->error < 0 || pending->truncated) {
		const char *filename = (const char *)pending->filename;
		long copied = bpf_probe_read_user_str(
		    event->path, sizeof(event->path), filename);
		if (copied < 0) {
			event->event_type = EVENT_TYPE_ERROR;
			event->error = copied;
			event->path[0] = '\0';
			bpf_ringbuf_submit(event, 0);
			bpf_map_delete_elem(&pending_opens, &pid_tgid);
			return 0;
		}
		event->error = 0;
		bpf_ringbuf_submit(event, 0);
		bpf_map_delete_elem(&pending_opens, &pid_tgid);
		return 0;
	}

	bpf_probe_read_kernel(event->path, sizeof(pending->path),
			      pending->path);

	bpf_ringbuf_submit(event, 0);
	bpf_map_delete_elem(&pending_opens, &pid_tgid);
	return 0;
}

/* Register sys_enter and sys_exit programs.
 *
 * Decode path pointer and CWD before passing it to util functions. */
SEC("tracepoint/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter *ctx) {
	return save_open_event((const char *)ctx->args[0], AT_FDCWD);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
	return save_open_event((const char *)ctx->args[1], (__s32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_openat2(struct trace_event_raw_sys_enter *ctx) {
	return save_open_event((const char *)ctx->args[1], (__s32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_open")
int trace_open_exit(struct trace_event_raw_sys_exit *ctx) {
	return submit_pending_open_event(ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_openat_exit(struct trace_event_raw_sys_exit *ctx) {
	return submit_pending_open_event(ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int trace_openat2_exit(struct trace_event_raw_sys_exit *ctx) {
	return submit_pending_open_event(ctx->ret);
}

/* sched_process_exec and sched_process_exit give userspace enough lifecycle
 * information to create/enrich ProcessInfo records around the open events.
 */
SEC("tracepoint/sched/sched_process_exec")
int trace_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
	propagate_daemon_tasks();

	if (!commandrun_should_trace()) {
		return 0;
	}

	struct file_open_event *event =
	    bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}
	event->event_type = EVENT_TYPE_EXEC;
	set_event_pids(event);
	event->cgroup_id = bpf_get_current_cgroup_id();
	event->dfd = 0;
	event->error = 0;

	__u16 filename_offset = ctx->__data_loc_filename & 0xffff;

	long copied = bpf_probe_read_kernel_str(
	    event->path, sizeof(event->path), (void *)ctx + filename_offset);

	if (copied < 0) {
		event->path[0] = '\0';
	}

	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(struct trace_event_raw_sys_exit *ctx) {
	if (!commandrun_should_trace()) {
		return 0;
	}

	struct file_open_event *event =
	    bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}
	event->event_type = EVENT_TYPE_EXIT;
	set_event_pids(event);
	event->cgroup_id = bpf_get_current_cgroup_id();

	event->dfd = 0;
	event->error = 0;
	event->path[0] = '\0';
	bpf_ringbuf_submit(event, 0);
	return 0;
}

/* Records new cgroups created system-wide. They are then marked enabled if it
 * was created by a process we were already tracing.
 */
SEC("tracepoint/cgroup/cgroup_mkdir")
int trace_cgroup_mkdir(struct trace_event_raw_cgroup *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;

	// If the PID creating this cgroup exists in our maps as a process of interest
	// store the cgroup in target_cgroups.
	if (!bpf_map_lookup_elem(&daemon_tasks, &tgid)) {
		return 0;
	}

	__u64 cgroup_id = ctx->id;
	__u8 enabled = 1;
	bpf_map_update_elem(&target_cgroups, &cgroup_id, &enabled, BPF_ANY);

	struct file_open_event *event =
	    bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}
	event->event_type = EVENT_TYPE_CGROUP_MKDIR;
	set_event_pids(event);
	event->cgroup_id = cgroup_id;
	event->dfd = 0;
	event->error = 0;

	__u16 path_offset = ctx->__data_loc_path & 0xffff;
	long copied = bpf_probe_read_kernel_str(
	    event->path, sizeof(event->path), (void *)ctx + path_offset);
	if (copied < 0) {
		event->path[0] = '\0';
	}

	bpf_ringbuf_submit(event, 0);
	return 0;
}

