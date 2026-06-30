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

#include "headers/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "headers/common.h"
#include "headers/maps.h"
#include "headers/map_defs.h"
#include "headers/helpers.h"

extern struct task_struct* bpf_task_from_pid(pid_t pid) __ksym;
extern void bpf_task_release(struct task_struct* task) __ksym;

// Handle sched_process_fork tracepoint
// When a process forks, if the parent is in tid_allowlist with nested_allowed,
// add the child to tid_allowlist as well
SEC("tracepoint/sched/sched_process_fork")
int handle_sched_process_fork(struct trace_event_raw_sched_process_fork* ctx) {
    // Parent is current task
    struct task_struct* parent = (struct task_struct*)bpf_get_current_task();
    __u32 parent_tid = get_tid_ns(parent);
    
    DEBUG_LOG("fork: parent_tid=%d child_pid=%d", parent_tid, ctx->child_pid);
    
    // Check if parent is in allowlist with nested_allowed
    struct tid_allowlist_key parent_key = {
        .tid = parent_tid,
    };

    struct tid_allowlist_val* parent_val = bpf_map_lookup_elem(&tid_allowlist, &parent_key);
    DEBUG_LOG("fork: parent_in_allowlist=%d nested=%d", parent_val != NULL, parent_val ? parent_val->nested_allowed : 0);
    if (parent_val && parent_val->nested_allowed) {
        // Get child's task struct using KFunc (kernel 6.12+)
        struct task_struct* child = bpf_task_from_pid(ctx->child_pid);
        if (!child) return 0;
        
        __u32 child_tid = get_tid_ns(child);
        
        struct tid_allowlist_key child_key = {
            .tid = child_tid,
        };
        struct tid_allowlist_val child_val = {
            .nested_allowed = parent_val->nested_allowed,
        };
        bpf_map_update_elem(&tid_allowlist, &child_key, &child_val, BPF_ANY);
        
        DEBUG_LOG("fork: child_tid=%d ADDED to tid_allowlist", child_tid);
        
        // From bpf docs:
        // If a task is returned, it must either be stored in a map, or released with bpf_task_release().
        bpf_task_release(child);
    }

    return 0;
}

// Handle sched_process_exit tracepoint
// Remove TID from allowlist when process exits
SEC("tracepoint/sched/sched_process_exit")
int handle_sched_process_exit(struct trace_event_raw_sched_process_exit* ctx) {
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    __u32 tid = get_tid_ns(task);

    DEBUG_LOG("exit: tid=%d REMOVED from tid_allowlist", tid);

    struct tid_allowlist_key key = {
        .tid = tid,
    };

    bpf_map_delete_elem(&tid_allowlist, &key);

    return 0;
}

static __always_inline int handle_sys_enter_exec(void) {
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    __u32 ns_tid = get_tid_ns(task);

    if (!is_tid_allowed(ns_tid)) {
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

    struct tid_allowlist_key old_key = {
        .tid = old_ns_tid,
    };

    // Was the background thread tracked before it called execve?
    struct tid_allowlist_val* old_val = bpf_map_lookup_elem(&tid_allowlist, &old_key);
    if (old_val) {
        // The background thread was tracked
        // It has now taken over the main Leader TID. We must re-add the new Leader ns_tid.
        struct task_struct* current_task = (struct task_struct*)bpf_get_current_task();
        __u32 new_ns_tid = get_tid_ns(current_task);

        struct tid_allowlist_key new_key = {
            .tid = new_ns_tid,
        };
        struct tid_allowlist_val new_val = {
            .nested_allowed = old_val->nested_allowed,
        };

        bpf_map_update_elem(&tid_allowlist, &new_key, &new_val, BPF_ANY);

        // Delete the old ghost ns_tid
        bpf_map_delete_elem(&tid_allowlist, &old_key);

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

char LICENSE[] SEC("license") = "Dual BSD/GPL";
