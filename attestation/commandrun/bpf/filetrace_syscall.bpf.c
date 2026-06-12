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
	if (!commandrun_in_target_cgroup()) {
		return 0;
	}

	__u64 pid_tgid = get_ns_pidtgid();
	struct pending_open pending = {
	    .filename = (__u64)filename,
	    .dfd = dfd,
	    .error = 0,
	};

	// Try to read the path buffer as a string on sys_enter for open.
	// If this fails the pending_open event is marked as such so that it can
	// be retried at sys_exit.
	long copied = bpf_probe_read_user_str(pending.path,
					      sizeof(pending.path), filename);
	if (copied < 0) {
		pending.error = copied;
		pending.path[0] = '\0';
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
	__u64 pid_tgid = get_ns_pidtgid();

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

	if (!commandrun_in_target_cgroup()) {
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
	event->pid = pid_tgid >> 32;
	event->tid = pid_tgid;
	event->dfd = pending->dfd;
	event->error = pending->error;

	// If reading the path failed at sys_enter, try that again here.
	// If this fails as well, return an error event.
	if (pending->error < 0) {
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

	__builtin_memcpy(event->path, pending->path, sizeof(event->path));
	event->path[sizeof(event->path) - 1] = '\0';

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
	if (!commandrun_in_target_cgroup()) {
		return 0;
	}

	struct file_open_event *event =
	    bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}
	__u64 pid_tgid = get_ns_pidtgid();
	event->event_type = EVENT_TYPE_EXEC;
	event->pid = pid_tgid >> 32;
	event->tid = pid_tgid;
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
int trace_sched_process_exit(struct sched_process_exit_args *ctx) {
	if (!commandrun_in_target_cgroup()) {
		return 0;
	}

	struct file_open_event *event =
	    bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}
	event->event_type = EVENT_TYPE_EXIT;

	__u64 pid_tgid = get_ns_pidtgid();
	event->pid = pid_tgid >> 32;
	event->tid = pid_tgid;

	event->dfd = 0;
	event->error = 0;
	event->path[0] = '\0';
	bpf_ringbuf_submit(event, 0);
	return 0;
}
