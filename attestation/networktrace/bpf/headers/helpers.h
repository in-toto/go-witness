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

#ifndef __HELPERS_H__
#define __HELPERS_H__

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "map_defs.h"
#include "vmlinux.h"

#define MAX_PARENT_WALK 64

static __always_inline __u64 get_injection_time(void) {
    __u32 key = 0;
    struct injection_time_val* val =
        bpf_map_lookup_elem(&injection_time_map, &key);
    if (val) return val->injection_time;
    return 0;
}

// Check if current task or any ancestor is in pid_allowlist
static __always_inline int is_pid_allowed(__u32 current_pid) {
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    if (!task) return 0;

    __u64 injection_time = get_injection_time();
    if (injection_time == 0) return 0;  // Not configured yet

    // First check: is current PID directly in the allowlist?
    __u64 start_time = BPF_CORE_READ(task, start_boottime);

    struct pid_allowlist_key key = {
        .pid = current_pid,
    };

    struct pid_allowlist_val* val = bpf_map_lookup_elem(&pid_allowlist, &key);
    // PID must be in allowlist AND must have started before injection_time
    // This prevents matching a different process that reused this PID after
    // monitoring started
    if (val && start_time < injection_time) return 1;

#pragma unroll
    for (int i = 0; i < MAX_PARENT_WALK; i++) {
        struct task_struct* parent = BPF_CORE_READ(task, real_parent);
        if (!parent) break;

        // tgid is the PID, getpid() returns tgid
        __u32 parent_pid = BPF_CORE_READ(parent, tgid);
        if (parent_pid <= 1) break;

        __u64 parent_start_time = BPF_CORE_READ(parent, start_boottime);

        key.pid = parent_pid;

        val = bpf_map_lookup_elem(&pid_allowlist, &key);
        // Parent must be in allowlist, allow nested, AND started before
        // injection_time
        if (val && val->nested_allowed && parent_start_time < injection_time)
            return 1;

        task = parent;
    }

    return 0;
}

static __always_inline int should_intercept(__u32 pid, __u64 cgroup_id,
                                            const char* comm) {
    // Check PID allowlist (with subtree walk)
    if (is_pid_allowed(pid)) {
        return 1;
    }

    struct cgroup_allowlist_key cg_key = {.cgroup_id = cgroup_id};
    __u8* cg_val = bpf_map_lookup_elem(&cgroup_allowlist, &cg_key);
    if (cg_val != NULL) {
        return 1;
    }

    struct comm_allowlist_key comm_key = {};
    __builtin_memcpy(comm_key.comm, comm, MAX_COMM_LEN);
    __u8* comm_val = bpf_map_lookup_elem(&comm_allowlist, &comm_key);
    if (comm_val != NULL) {
        return 1;
    }

    return 0;
}

static __always_inline __u32 get_netns_inum(struct task_struct* task) {
    struct nsproxy* nsproxy;
    struct net* net_ns;
    __u32 inum = 0;

    if (!task) return 0;

    nsproxy = BPF_CORE_READ(task, nsproxy);
    if (!nsproxy) return 0;

    net_ns = BPF_CORE_READ(nsproxy, net_ns);
    if (!net_ns) return 0;

    inum = BPF_CORE_READ(net_ns, ns.inum);

    return inum;
}

#endif /* __HELPERS_H__ */