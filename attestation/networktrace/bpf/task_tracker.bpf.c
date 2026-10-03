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

static __always_inline struct control_val* get_control(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&control_map, &key);
}

// publish_lifecycle_terminal claims the first terminal transition, disables
// new interception synchronously, and publishes terminal status last.
static __always_inline void publish_lifecycle_terminal(__u64 terminal_status, __u64 error) {
    struct control_val* control = get_control();
    if (!control) return;
    if (__sync_val_compare_and_swap(&control->lifecycle_status, LIFECYCLE_RUNNING,
                                    LIFECYCLE_TRANSITIONING) != LIFECYCLE_RUNNING) {
        return;
    }
    control->terminal_ts_ns = bpf_ktime_get_ns();
    __sync_lock_test_and_set(&control->tracing_disabled, 1);
    control->lifecycle_error = error;
    __sync_lock_test_and_set(&control->lifecycle_status, terminal_status);
}

static __always_inline void fail_lifecycle(__u64 error) {
    publish_lifecycle_terminal(LIFECYCLE_FAILED, error);
}

// Handle sched_process_fork tracepoint.
//
// Within the witness PID namespace: if the parent is in
// witness_pid_ns_tid_allowlist with nested_allowed, add the child to
// witness_pid_ns_tid_allowlist.
//
// For processes in PID namespaces already tracked via tracked_pid_ns_map:
// propagate tracking to any new PID namespace the child creates (CLONE_NEWPID).
//
// Independently of capture, every fork of a tracked_tasks member extends the
// command tree liveness: capture filters never gate the live-task count.
SEC("tracepoint/sched/sched_process_fork")
int handle_sched_process_fork(struct trace_event_raw_sched_process_fork* ctx) {
    // Parent is current task
    struct task_struct* parent = (struct task_struct*)bpf_get_current_task();
    __u32 parent_tid = get_tid_ns(parent);
    __u32 parent_pid_ns = get_pid_ns_inum(parent);

    DEBUG_LOG("fork: parent_tid=%d parent_pid_ns=%u child_pid=%d", parent_tid, parent_pid_ns, ctx->child_pid);

    int capture_parent = 0;
    if (parent_pid_ns == witness_pid_ns_inum) {
        struct witness_pid_ns_tid_key parent_key = {
            .tid = parent_tid,
        };
        struct witness_pid_ns_tid_val* parent_val = bpf_map_lookup_elem(&witness_pid_ns_tid_allowlist, &parent_key);
        if (parent_val && parent_val->nested_allowed) {
            capture_parent = 1;
        }
        DEBUG_LOG("fork: witness-ns parent_in_allowlist=%d nested=%d", parent_val != NULL, parent_val ? parent_val->nested_allowed : 0);
    } else if (is_pid_ns_tracked(parent_pid_ns)) {
        capture_parent = 1;
        DEBUG_LOG("fork: descendant-ns parent tracked");
    }

    __u32 parent_witness_tid = get_witness_tid(parent);
    __u8* parent_member = parent_witness_tid ? bpf_map_lookup_elem(&tracked_tasks, &parent_witness_tid) : NULL;
    struct control_val* control = get_control();
    int lifecycle_parent = parent_member && control &&
                           control->lifecycle_status == LIFECYCLE_RUNNING;

    if (!capture_parent && !lifecycle_parent) return 0;

    struct task_struct* child = bpf_task_from_pid(ctx->child_pid);
    if (!child) {
        if (lifecycle_parent) fail_lifecycle(LIFECYCLE_ERROR_TASK_IDENTITY);
        return 0;
    }

    __u32 child_pid_ns = get_pid_ns_inum(child);

    if (capture_parent) {
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
    }

    if (lifecycle_parent) {
        __u32 child_witness_tid = get_witness_tid(child);
        __u8 one = 1;
        if (!child_witness_tid) {
            fail_lifecycle(LIFECYCLE_ERROR_TASK_IDENTITY);
        } else if (bpf_map_update_elem(&tracked_tasks, &child_witness_tid, &one, BPF_NOEXIST) != 0) {
            fail_lifecycle(LIFECYCLE_ERROR_TASK_INSERT);
        } else if (control->lifecycle_status == LIFECYCLE_RUNNING) {
            __sync_fetch_and_add(&control->live_tasks, 1);
        } else {
            // This delete is for race condition between two CPUs, where another
            // CPU might terminate the process and receieve the signal, in that case
            // tihs needs to be deleted from the tracked tasks.
            bpf_map_delete_elem(&tracked_tasks, &child_witness_tid);
        }
    }

    bpf_task_release(child);
    return 0;
}

// Handle sched_process_exit tracepoint.
// Remove TID from witness_pid_ns_tid_allowlist and gate_map. If the exiting
// task is the init process (PID 1) of a tracked PID namespace, the namespace
// is being torn down, remove it from tracked_pid_ns_map.
//
// A tracked_tasks member additionally decrements the live count; the unique
// atomic 1 -> 0 transition publishes the successful tree exit.
SEC("tracepoint/sched/sched_process_exit")
int handle_sched_process_exit(struct trace_event_raw_sched_process_exit* ctx) {
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    __u32 tid = get_tid_ns(task);
    __u32 netns_inum = get_netns_inum(task);
    __u32 pid_ns = get_pid_ns_inum(task);
    __u32 witness_tid = get_witness_tid(task);

    DEBUG_LOG("exit: tid=%d pid_ns=%u", tid, pid_ns);

    if (witness_tid && bpf_map_delete_elem(&tracked_tasks, &witness_tid) == 0) {
        struct control_val* control = get_control();
        if (!control) return 0;
        if (control->lifecycle_status == LIFECYCLE_RUNNING) {
            __u64 old = __sync_fetch_and_sub(&control->live_tasks, 1);
            if (old == 0) {
                fail_lifecycle(LIFECYCLE_ERROR_COUNTER_UNDERFLOW);
            } else if (old == 1) {
                publish_lifecycle_terminal(LIFECYCLE_EXITED, LIFECYCLE_ERROR_NONE);
            }
        }
    }

    // Only witness-namespace TIDs are keys in this allowlist. A descendant
    // namespace's local TID may numerically collide with an unrelated key.
    if (pid_ns == witness_pid_ns_inum) {
        struct witness_pid_ns_tid_key key = {
            .tid = tid,
        };
        bpf_map_delete_elem(&witness_pid_ns_tid_allowlist, &key);
    }

    // If the task is exiting while it still has a pending gate entry (e.g. it
    // was killed while frozen), drop the entry so userspace stops trying to
    // wake a dead task.
    struct gate_key gkey = {
        .netns_inum = netns_inum,
        .tid = tid,
    };
    bpf_map_delete_elem(&gate_map, &gkey);

    if (is_pid_ns_tracked(pid_ns)) {
        __u32 ns_pid = get_ns_pid(task);
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

    int capture_tracked = 0;
    if (pid_ns == witness_pid_ns_inum) {
        capture_tracked = is_witness_pid_ns_tid_allowed(ns_tid);
    } else {
        capture_tracked = is_pid_ns_tracked(pid_ns);
    }

    __u32 witness_tid = get_witness_tid(task);
    __u8* lifecycle_member = witness_tid ? bpf_map_lookup_elem(&tracked_tasks, &witness_tid) : NULL;

    if (!capture_tracked && !lifecycle_member) {
        return 0;
    }

    // Save it to the bridge map so we can rescue it during the swap.
    __u32 global_tid = (__u32)bpf_get_current_pid_tgid();
    struct pending_exec_val pending = {
        .ns_tid = ns_tid,
        .witness_tid = witness_tid,
    };
    bpf_map_update_elem(&pending_execs, &global_tid, &pending, BPF_ANY);

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
    struct pending_exec_val* pending_ptr = bpf_map_lookup_elem(&pending_execs, &global_old_tid);

    if (!pending_ptr) {
        return 0;
    }

    // Copy the map-backed value before any update invalidates the pointer.
    struct pending_exec_val pending = *pending_ptr;
    struct task_struct* current_task = (struct task_struct*)bpf_get_current_task();

    // Was the background thread tracked before it called execve? The allowlist
    // is keyed by witness-namespace TID, so the rescue only applies when the
    // execing task lives in the witness PID namespace: a descendant namespace's
    // local TID may numerically collide with an unrelated key, and descendant
    // capture is governed by tracked_pid_ns_map wholesale.
    if (get_pid_ns_inum(current_task) == witness_pid_ns_inum) {
        struct witness_pid_ns_tid_key old_capture_key = {
            .tid = pending.ns_tid,
        };
        struct witness_pid_ns_tid_val* old_capture = bpf_map_lookup_elem(&witness_pid_ns_tid_allowlist, &old_capture_key);
        if (old_capture) {
            // The background thread was tracked. It has now taken over the main
            // Leader TID. We must re-add the new Leader ns_tid.
            __u8 nested_allowed = old_capture->nested_allowed;
            __u32 new_ns_tid = get_tid_ns(current_task);
            struct witness_pid_ns_tid_key new_capture_key = {
                .tid = new_ns_tid,
            };
            struct witness_pid_ns_tid_val new_capture = {
                .nested_allowed = nested_allowed,
            };

            // Add-new BEFORE delete-old so that a concurrent connect on the new
            // TID never sees a window where neither key is present.
            bpf_map_update_elem(&witness_pid_ns_tid_allowlist, &new_capture_key, &new_capture, BPF_ANY);

            // Delete the old ghost ns_tid
            bpf_map_delete_elem(&witness_pid_ns_tid_allowlist, &old_capture_key);

            DEBUG_LOG("exec: rescued ghost ns_tid=%d -> new ns_tid=%d", pending.ns_tid, new_ns_tid);
        }
    }

    // Migrate liveness membership to the post-exec identity without changing
    // the live count: one live task changed TID.
    if (pending.witness_tid) {
        __u8* old_member = bpf_map_lookup_elem(&tracked_tasks, &pending.witness_tid);
        if (old_member) {
            __u32 new_witness_tid = get_witness_tid(current_task);
            __u8 one = 1;
            if (!new_witness_tid) {
                fail_lifecycle(LIFECYCLE_ERROR_TASK_IDENTITY);
            } else if (new_witness_tid != pending.witness_tid) {
                if (bpf_map_update_elem(&tracked_tasks, &new_witness_tid, &one, BPF_NOEXIST) != 0) {
                    fail_lifecycle(LIFECYCLE_ERROR_EXEC_MIGRATION);
                } else if (bpf_map_delete_elem(&tracked_tasks, &pending.witness_tid) != 0) {
                    bpf_map_delete_elem(&tracked_tasks, &new_witness_tid);
                    fail_lifecycle(LIFECYCLE_ERROR_EXEC_MIGRATION);
                }
            }
        }
    }

    // The old global TID key is unreachable after a successful identity swap.
    bpf_map_delete_elem(&pending_execs, &global_old_tid);
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
