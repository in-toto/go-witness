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

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "headers/common.h"
#include "headers/maps.h"
#include "headers/map_defs.h"
#include "headers/helpers.h"

extern struct task_struct* bpf_task_from_pid(pid_t pid) __ksym;
extern void bpf_task_release(struct task_struct* task) __ksym;

// Handle sched_process_fork tracepoint.
//
// Within the witness PID namespace: if the parent is in
// witness_pid_ns_tid_allowlist with nested_allowed, add the child to
// witness_pid_ns_tid_allowlist.
//
// For processes in PID namespaces already tracked via tracked_pid_ns_map:
// propagate tracking to any new PID namespace the child creates (CLONE_NEWPID).
SEC("tracepoint/sched/sched_process_fork")
int handle_sched_process_fork(struct trace_event_raw_sched_process_fork* ctx) {
    // Parent is current task
    struct task_struct* parent = (struct task_struct*)bpf_get_current_task();
    __u32 parent_tid = get_tid_ns(parent);
    __u32 parent_pid_ns = get_pid_ns_inum(parent);

    DEBUG_LOG("fork: parent_tid=%d parent_pid_ns=%u child_pid=%d", parent_tid, parent_pid_ns, ctx->child_pid);

    int parent_tracked = 0;
    if (parent_pid_ns == witness_pid_ns_inum) {
        struct witness_pid_ns_tid_key parent_key = {
            .tid = parent_tid,
        };
        struct witness_pid_ns_tid_val* parent_val = bpf_map_lookup_elem(&witness_pid_ns_tid_allowlist, &parent_key);
        if (parent_val && parent_val->nested_allowed) {
            parent_tracked = 1;
        }
        DEBUG_LOG("fork: witness-ns parent_in_allowlist=%d nested=%d", parent_val != NULL, parent_val ? parent_val->nested_allowed : 0);
    } else if (is_pid_ns_tracked(parent_pid_ns)) {
        parent_tracked = 1;
        DEBUG_LOG("fork: descendant-ns parent tracked");
    }

    if (parent_tracked) {
        struct task_struct* child = bpf_task_from_pid(ctx->child_pid);
        if (!child) return 0;

        __u32 child_pid_ns = get_pid_ns_inum(child);

        if (child_pid_ns != parent_pid_ns) {
            __u8 one = 1;
            bpf_map_update_elem(&tracked_pid_ns_map, &child_pid_ns, &one, BPF_ANY);
            DEBUG_LOG("fork: marked child_pid_ns=%u as tracked", child_pid_ns);
        } else if (parent_pid_ns == witness_pid_ns_inum) {
            __u32 child_tid = get_tid_ns(child);
            struct witness_pid_ns_tid_key child_key = {
                .tid = child_tid,
            };
            struct witness_pid_ns_tid_val child_val = {
                .nested_allowed = 1,
            };
            bpf_map_update_elem(&witness_pid_ns_tid_allowlist, &child_key, &child_val, BPF_ANY);
            DEBUG_LOG("fork: child_tid=%d ADDED to witness_pid_ns_tid_allowlist", child_tid);
        }

        bpf_task_release(child);
    }

    return 0;
}

// Handle sched_process_exit tracepoint.
// Remove TID from witness_pid_ns_tid_allowlist and gate_map. If the exiting
// task is the init process (PID 1) of a tracked PID namespace, the namespace
// is being torn down, remove it from tracked_pid_ns_map.
SEC("tracepoint/sched/sched_process_exit")
int handle_sched_process_exit(struct trace_event_raw_sched_process_exit* ctx) {
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    __u32 tid = get_tid_ns(task);
    __u32 netns_inum = get_netns_inum(task);
    __u32 pid_ns = get_pid_ns_inum(task);

    DEBUG_LOG("exit: tid=%d pid_ns=%u", tid, pid_ns);

    struct witness_pid_ns_tid_key key = {
        .tid = tid,
    };

    bpf_map_delete_elem(&witness_pid_ns_tid_allowlist, &key);

    // If the task is exiting while it still has a pending gate entry (e.g. it
    // was killed while frozen), drop the entry so userspace stops trying to
    // wake a dead task.
    struct gate_key gkey = {
        .netns_inum = netns_inum,
        .tid = tid,
    };
    bpf_map_delete_elem(&gate_map, &gkey);

    if (is_pid_ns_tracked(pid_ns)) {
        __u32 ns_pid = get_pid_ns(task);
        if (ns_pid == 1 && tid == 1) {
            bpf_map_delete_elem(&tracked_pid_ns_map, &pid_ns);
            DEBUG_LOG("exit: removed tracked_pid_ns=%u (init exited)", pid_ns);
        }
    }

    return 0;
}

static __always_inline int handle_sys_enter_exec(void) {
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    __u32 ns_tid = get_tid_ns(task);
    __u32 pid_ns = get_pid_ns_inum(task);

    // Populate the witness PID ns absolute level once so descendant
    // netns_gate invocations can directly index thread_pid.numbers[].
    if (pid_ns == witness_pid_ns_inum) {
        __u32 key = 0;
        __u32* existing = bpf_map_lookup_elem(&witness_pid_ns_level_map, &key);
        if (!existing) {
            struct pid* tp = BPF_CORE_READ(task, group_leader, thread_pid);
            if (tp) {
                __u32 wlevel = BPF_CORE_READ(tp, level);
                bpf_map_update_elem(&witness_pid_ns_level_map, &key, &wlevel, BPF_ANY);
            }
        }
    }

    int tracked = 0;

    if (pid_ns == witness_pid_ns_inum) {
        if (is_witness_pid_ns_tid_allowed(ns_tid)) {
            tracked = 1;
        }
    } else if (is_pid_ns_tracked(pid_ns)) {
        tracked = 1;
    }

    if (!tracked) {
        return 0;
    }

    // Save it to the bridge map so we can rescue it during the swap.
    __u32 global_tid = (__u32)bpf_get_current_pid_tgid();
    bpf_map_update_elem(&pending_execs, &global_tid, &ns_tid, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(void *ctx) { return handle_sys_enter_exec(); }

SEC("tracepoint/syscalls/sys_enter_execveat")
int sys_enter_execveat(void *ctx) { return handle_sys_enter_exec(); }

SEC("tracepoint/sched/sched_process_exec")
int handle_sched_process_exec(struct trace_event_raw_sched_process_exec* ctx) {
    // If a single-threaded program calls execve, the TID doesn't change.
    if (ctx->old_pid == ctx->pid) {
        return 0;
    }

    // Look up the old Global TID in our pending_execs map to get the old ns_tid
    __u32 global_old_tid = ctx->old_pid;
    __u32* old_ns_tid_ptr = bpf_map_lookup_elem(&pending_execs, &global_old_tid);

    if (!old_ns_tid_ptr) {
        return 0;
    }

    __u32 old_ns_tid = *old_ns_tid_ptr;

    struct task_struct* current_task = (struct task_struct*)bpf_get_current_task();

    struct witness_pid_ns_tid_key old_key = {
        .tid = old_ns_tid,
    };

    // Was the background thread tracked before it called execve?
    struct witness_pid_ns_tid_val* old_val = bpf_map_lookup_elem(&witness_pid_ns_tid_allowlist, &old_key);
    if (old_val) {
        // The background thread was tracked. It has now taken over the main
        // Leader TID. We must re-add the new Leader ns_tid.
        __u32 new_ns_tid = get_tid_ns(current_task);

        struct witness_pid_ns_tid_key new_key = {
            .tid = new_ns_tid,
        };
        struct witness_pid_ns_tid_val new_val = {
            .nested_allowed = old_val->nested_allowed,
        };

        // Add-new BEFORE delete-old so that a concurrent connect on the new
        // TID never sees a window where neither key is present.
        bpf_map_update_elem(&witness_pid_ns_tid_allowlist, &new_key, &new_val, BPF_ANY);

        // Delete the old ghost ns_tid
        bpf_map_delete_elem(&witness_pid_ns_tid_allowlist, &old_key);

        DEBUG_LOG("exec: rescued ghost ns_tid=%d -> new ns_tid=%d", old_ns_tid, new_ns_tid);
    }

    return 0;
}

static __always_inline int handle_sys_exit_exec(void) {
    __u32 global_tid = (__u32)bpf_get_current_pid_tgid();

    bpf_map_delete_elem(&pending_execs, &global_tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int sys_exit_execve(void *ctx) { return handle_sys_exit_exec(); }

SEC("tracepoint/syscalls/sys_exit_execveat")
int sys_exit_execveat(void *ctx) { return handle_sys_exit_exec(); }

// Network-namespace gate anchors.
//
// A task's network namespace can only change through clone/clone3 (a new task
// born in a new netns), or unshare/setns (the current task moving to another
// netns). Each of these tracepoints fires on the kernel->user return path of
// the syscall, so a SIGSTOP queued here via bpf_send_signal is delivered before
// the task executes any userspace instruction i.e. before it can call
// connect(). gate_if_unready freezes the task if its (new) netns has no ready
// proxy, giving userspace time to inject one.

// For clone/clone3 the tracepoint fires in BOTH the parent (ret == child pid)
// and the child (ret == 0). We only act on the child path: the child is the
// task that may have been placed into a new netns, and it is the task we must
// freeze in its own context as bpf_send_signal only works for the current task.
SEC("tracepoint/syscalls/sys_exit_clone")
int sys_exit_clone(struct trace_event_raw_sys_exit* ctx) {
    if (ctx->ret != 0) {
        return 0;
    }
    return gate_if_unready();
}

SEC("tracepoint/syscalls/sys_exit_clone3")
int sys_exit_clone3(struct trace_event_raw_sys_exit* ctx) {
    if (ctx->ret != 0) {
        return 0;
    }
    return gate_if_unready();
}

// unshare/setns run in the current task's context; on success the task's netns
// has already changed by the time this exit tracepoint fires. A failed call
// leaves the task in its original netns (whose proxy is ready), so the gate is
// a no-op and we do not need to inspect ctx->ret.
SEC("tracepoint/syscalls/sys_exit_unshare")
int sys_exit_unshare(struct trace_event_raw_sys_exit* ctx) {
    return gate_if_unready();
}

SEC("tracepoint/syscalls/sys_exit_setns")
int sys_exit_setns(struct trace_event_raw_sys_exit* ctx) {
    return gate_if_unready();
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
