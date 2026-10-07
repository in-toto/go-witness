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

#define MAX_PATH_DEPTH 32
#define NAME_MAX 256

/* resolve_fd_path return enum */
#define RESOLVE_SKIP 0       // pipes, sockets, etc.
#define RESOLVE_UNRESOLVED -1 // use raw `path` argument passed to open

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Pending opens are used to retain state between sys_entry and sys_exit
// tracepoint functions.
//
// State retention between these functions is only required so the path passed
// to open can be read at sys_exit, when the fd can't be resolved to a path.
struct pending_open {
	__u64 filename;
	__s32 dfd;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192 * 12);
	__type(key, __u64);
	__type(value, struct pending_open);
} pending_opens SEC(".maps");

// Called on sys_enter for open* paths.
// - Store pending_open to be decoded upon sys_exit
static __always_inline int save_open_event(const char *filename, __s32 dfd) {
	if (!commandrun_should_trace()) {
		return 0;
	}

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pending_open pending = {
	    .filename = (__u64)filename,
	    .dfd = dfd,
	};

	long update_ret =
	    bpf_map_update_elem(&pending_opens, &pid_tgid, &pending, BPF_ANY);
	if (update_ret < 0) {
		submit_error_event(ERROR_TYPE_PENDING_OPEN_UPDATE);
	}
	return 0;
}

static __always_inline struct mount *real_mount(struct vfsmount *vmnt) {
	return (void *)vmnt - bpf_core_field_offset(struct mount, mnt);
}

/* Resolve fd to a path relative to the task's root and write it to data[] as
 * \0-separated components. 
 * 
 * Mount boundaries are crossed here, so userspace doesn't need race-y
 * /proc/<pid>/{cwd,fd,root} lookups.
 *
 * Returns:
 * 	RESOLVE_SKIP:	Unhashable file, not reported to userspace (pipes, sockets)
 * 	RESOLVE_UNRESOLVED:	Unable to construct absolute path (for a hashable file)
 * 	>0:	Length of the string stored in data[]
 */
static __always_inline __u32 resolve_fd_path(struct file_open_event *event, __s64 fd) {
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);
	if (!fdt || fd < 0 || fd >= BPF_CORE_READ(fdt, max_fds)) {
		return RESOLVE_UNRESOLVED;
	}
	struct file **fds = BPF_CORE_READ(fdt, fd);
	struct file *file = NULL;
	if (bpf_core_read(&file, sizeof(file), &fds[fd]) || !file) {
		return RESOLVE_UNRESOLVED;
	}

	struct dentry *root_dentry = BPF_CORE_READ(task, fs, root.dentry);
	struct vfsmount *root_vmnt = BPF_CORE_READ(task, fs, root.mnt);
	struct dentry *cur_dentry = BPF_CORE_READ(file, f_path.dentry);
	struct vfsmount *cur_vmnt = BPF_CORE_READ(file, f_path.mnt);
	struct mount *cur_mnt = real_mount(cur_vmnt);
	__u32 off = 0;

	for (int i = 0; i < MAX_PATH_DEPTH; i++) {
		// Reached the task's root (check same vmount for mount --bind style mounts) 
		if (cur_dentry == root_dentry && cur_vmnt == root_vmnt) {
			return off;
		}
		if (cur_dentry == BPF_CORE_READ(cur_vmnt, mnt_root)) {
			// Top of this mount, continue from its "parent" mount.
			struct mount *parent_mnt = BPF_CORE_READ(cur_mnt, mnt_parent);
			// Mount is its own parent (namespace top or detached)
			if (parent_mnt == cur_mnt) {
				return RESOLVE_UNRESOLVED;
			}
			cur_dentry = BPF_CORE_READ(cur_mnt, mnt_mountpoint);
			cur_mnt = parent_mnt;
			cur_vmnt = &parent_mnt->mnt;
			continue;
		}
		struct dentry *parent_dentry = BPF_CORE_READ(cur_dentry, d_parent);
		
		// Pseudo-fs dentries (pipes, sockets) are their own parent.
		if (parent_dentry == cur_dentry) {
			return RESOLVE_SKIP;
		}

		if(off > sizeof(event->data) - NAME_MAX) {
			return RESOLVE_UNRESOLVED;
		}
		long name_len = bpf_probe_read_kernel_str(&event->data[off], NAME_MAX,
							  BPF_CORE_READ(cur_dentry, d_name.name));
		if (name_len <= 0) {
			return RESOLVE_UNRESOLVED;
		}

		off += name_len;
		cur_dentry = parent_dentry;
	}
	return RESOLVE_UNRESOLVED;
}

/* Called on sys_exit for open* syscalls. If an absolute path can be resolved from
 * the fd, emit EVENT_TYPE_OPEN otherwise EVENT_TYPE_OPEN_RAW.
 */
static __always_inline int submit_open_event(__s64 ret) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pending_open *pending =
	    bpf_map_lookup_elem(&pending_opens, &pid_tgid);
	__u64 filename = pending ? pending->filename : 0;
	bpf_map_delete_elem(&pending_opens, &pid_tgid);

	if (ret < 0 || !commandrun_should_trace()) {
		return 0;
	}

	struct file_open_event *event = reserve_event(EVENT_TYPE_OPEN);
	if (!event) {
		return 0;
	}

	// Userspace hashes the path in data[] under the root identified here.
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	event->root_ino = BPF_CORE_READ(task, fs, root.dentry, d_inode, i_ino);
	struct mount *root_mnt = real_mount(BPF_CORE_READ(task, fs, root.mnt));
	event->root_mnt_id = BPF_CORE_READ(root_mnt, mnt_id);

	__u32 len = resolve_fd_path(event, ret);
	if (len == RESOLVE_SKIP) {
		bpf_ringbuf_discard(event, 0);
		return 0;
	}
	if (len == RESOLVE_UNRESOLVED) {
		// No sys_enter entry (evicted, or tracing started mid-syscall).
		if (!filename) {
			bpf_ringbuf_discard(event, 0);
			submit_error_event(ERROR_TYPE_PENDING_OPEN_MISSING);
			return 0;
		}
		long copied = bpf_probe_read_user_str(event->data, sizeof(event->data),
						      (const char *)filename);
		// Filename unreadable
		if (copied <= 0) {
			event->event_type = EVENT_TYPE_ERROR;
			event->error = copied;
			event->data_len = 0;
			bpf_ringbuf_submit(event, 0);
			return 0;
		}
		event->event_type = EVENT_TYPE_OPEN_RAW;
		len = copied;
	}

	event->data_len = len;
	bpf_ringbuf_submit(event, 0);
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
	return submit_open_event(ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_openat_exit(struct trace_event_raw_sys_exit *ctx) {
	return submit_open_event(ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int trace_openat2_exit(struct trace_event_raw_sys_exit *ctx) {
	return submit_open_event(ctx->ret);
}

/* Propagate newly forked task from a daemon. Raw tracepoint so we get the child
 * task_struct and can resolve its TGID in witness's PID namespace. New threads
 * resolve to their parent's TGID, which is already tracked.
 */
SEC("raw_tracepoint/sched_process_fork")
int trace_sched_process_fork(struct bpf_raw_tracepoint_args *ctx) {
	struct task_struct *parent = (struct task_struct *)ctx->args[0];
	struct task_struct *child = (struct task_struct *)ctx->args[1];
	propagate_daemon_task(witness_ns_tgid(parent), witness_ns_tgid(child));
	return 0;
}

/* sched_process_exec gives userspace enough lifecycle information to
 * create ProcessInfo records.
 */
SEC("tracepoint/sched/sched_process_exec")
int trace_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
	// Propagate daemon tasks on both fork and exec.
	struct task_struct *self = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = BPF_CORE_READ(self, real_parent);
	__u32 parent_tgid = parent ? witness_ns_tgid(parent) : 0;
	propagate_daemon_task(parent_tgid, current_witness_ns_tgid());

	if (!commandrun_should_trace()) {
		return 0;
	}

	struct file_open_event *event = reserve_event(EVENT_TYPE_EXEC);
	if (!event) {
		return 0;
	}

	__u16 filename_offset = ctx->__data_loc_filename & 0xffff;

	// The format for exec's data is: "filename\0argv..."
	long copied = bpf_probe_read_kernel_str(
	    event->data, EXEC_PART_MAX, (void *)ctx + filename_offset);
	if (copied <= 0) {
		event->data[0] = '\0';
		copied = 1;
	}
	__u32 off = copied & EXEC_PART_MAX;
	event->data_len = off;

	// Equivalent of reading the /proc/<pid>/cmdline but avoids the race in
	// userspace for short lived processes exiting before the event loop gets
	// to this exec event.
	struct mm_struct *mm = BPF_CORE_READ(self, mm);
	unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
	unsigned long len = BPF_CORE_READ(mm, arg_end) - arg_start;
	if (len > EXEC_PART_MAX) {
		len = EXEC_PART_MAX;
	}
	len &= EXEC_PART_MAX;
	if (len > 0 && bpf_probe_read_user(&event->data[off], len,
					   (void *)arg_start) == 0) {
		event->data_len = off + len;
	}

	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(struct trace_event_raw_sys_exit *ctx) {
	if (!commandrun_should_trace()) {
		return 0;
	}

	// do_exit() runs before this tracepoint, so signal->live is already decremented.
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u32 group_dead = BPF_CORE_READ(task, signal, live.counter) == 0;

	// Remove from daemon_tasks map.
	if (group_dead) {
		__u32 tgid = current_witness_ns_tgid();
		bpf_map_delete_elem(&daemon_tasks, &tgid);
	}

	struct file_open_event *event =
	    reserve_event(group_dead ? EVENT_TYPE_GROUP_EXIT : EVENT_TYPE_EXIT);
	if (!event) {
		return 0;
	}
	bpf_ringbuf_submit(event, 0);
	return 0;
}

/* Records new cgroups created system-wide. They are then marked enabled if it
 * was created by a process we were already tracing.
 */
SEC("tracepoint/cgroup/cgroup_mkdir")
int trace_cgroup_mkdir(struct trace_event_raw_cgroup *ctx) {
	// If the PID creating this cgroup exists in our maps as a process of interest
	// store the cgroup in target_cgroups.
	if (!is_daemon_task()) {
		return 0;
	}

	__u64 cgroup_id = ctx->id;
	__u8 enabled = 1;
	bpf_map_update_elem(&target_cgroups, &cgroup_id, &enabled, BPF_ANY);

	struct file_open_event *event = reserve_event(EVENT_TYPE_CGROUP_MKDIR);
	if (!event) {
		return 0;
	}
	// The new cgroup, not the creating task's.
	event->cgroup_id = cgroup_id;

	__u16 path_offset = ctx->__data_loc_path & 0xffff;
	long copied = bpf_probe_read_kernel_str(
	    event->data, sizeof(event->data), (void *)ctx + path_offset);
	event->data_len = copied > 0 ? copied : 0;

	bpf_ringbuf_submit(event, 0);
	return 0;
}

/* Cgroup removed: stop tracking it. */
SEC("tracepoint/cgroup/cgroup_rmdir")
int trace_cgroup_rmdir(struct trace_event_raw_cgroup *ctx) {
	__u64 cgroup_id = ctx->id;
	bpf_map_delete_elem(&target_cgroups, &cgroup_id);
	return 0;
}

