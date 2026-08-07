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

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "map_defs.h"
#include "common.h"

volatile const __u32 witness_pid_ns_inum = 0;  // to be set from user-space

static __always_inline int is_tracing_disabled(void) {
    __u32 zero = 0;
    struct control_val* ctrl = bpf_map_lookup_elem(&control_map, &zero);
    if (ctrl && ctrl->tracing_disabled) {
        return 1;
    }
    return 0;
}

static __always_inline __u32 get_pid_ns_inum(struct task_struct* task) {
    struct pid* tp = BPF_CORE_READ(task, group_leader, thread_pid);
    if (!tp) return 0;
    unsigned int level = BPF_CORE_READ(tp, level);
    struct pid_namespace* pid_ns = BPF_CORE_READ(tp, numbers[level].ns);
    if (!pid_ns) return 0;
    return BPF_CORE_READ(pid_ns, ns.inum);
}

static __always_inline int is_pid_ns_tracked(__u32 pid_ns_inum) {
    __u8* v = bpf_map_lookup_elem(&tracked_pid_ns_map, &pid_ns_inum);
    return v != NULL;
}

static __always_inline __u32 get_pid_ns(struct task_struct* task) {
  struct task_struct* leader = BPF_CORE_READ(task, group_leader);

  unsigned int level = BPF_CORE_READ(leader, thread_pid, level);
  __u32 ns_pid = BPF_CORE_READ(leader, thread_pid, numbers[level].nr);
  return ns_pid;
}

static __always_inline __u32 get_tid_ns(struct task_struct* task) {
  unsigned int level = BPF_CORE_READ(task, thread_pid, level);
  __u32 ns_tid = BPF_CORE_READ(task, thread_pid, numbers[level].nr);
  return ns_tid;
}

static __always_inline int is_witness_pid_ns_tid_allowed(__u32 tid) {
    struct witness_pid_ns_tid_key key = {
        .tid = tid,
    };

    struct witness_pid_ns_tid_val* val = bpf_map_lookup_elem(&witness_pid_ns_tid_allowlist, &key);
    if (val) return 1;

    return 0;
}

static __always_inline int should_intercept(__u32 pid_ns_inum, __u32 netns_inum, __u32 tid,
                                            __u64 cgroup_id, const char* comm) {
    DEBUG_LOG("should_intercept: ENTER pid_ns=%u tid=%d cgroup=%llu comm=%s", pid_ns_inum, tid, cgroup_id, comm);

    if (pid_ns_inum == witness_pid_ns_inum) {
        // Witness PID namespace, apply per-TID/comm/cgroup filters.
        if (is_witness_pid_ns_tid_allowed(tid)) {
            DEBUG_LOG("should_intercept: ALLOWED tid=%d (witness_pid_ns_tid_allowlist)", tid);
            return 1;
        }

        struct cgroup_allowlist_key cg_key = {.cgroup_id = cgroup_id};
        __u8* cg_val = bpf_map_lookup_elem(&cgroup_allowlist, &cg_key);
        if (cg_val != NULL) {
            DEBUG_LOG("should_intercept: ALLOWED cgroup=%llu", cgroup_id);
            return 1;
        }

        struct comm_allowlist_key comm_key = {};
        __builtin_memcpy(comm_key.comm, comm, MAX_COMM_LEN);
        __u8* comm_val = bpf_map_lookup_elem(&comm_allowlist, &comm_key);
        if (comm_val != NULL) {
            DEBUG_LOG("should_intercept: ALLOWED comm=%s", comm);
            return 1;
        }
    } else if (is_pid_ns_tracked(pid_ns_inum)) {
        // Descendant PID namespace created by a tracked process, intercept
        // everything unconditionally.
        DEBUG_LOG("should_intercept: ALLOWED pid_ns=%u (tracked descendant)", pid_ns_inum);
        return 1;
    }

    DEBUG_LOG("should_intercept: DENIED pid_ns=%u tid=%d cgroup=%llu comm=%s", pid_ns_inum, tid, cgroup_id, comm);
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

// netns_gate freezes a tracked task whose network namespace does not yet have
// a ready proxy, and records a durable request for userspace to set one up.
//
// Because Go flips READY before sweeping, and eBPF publishes its gate entry
// before re-checking READY, every task is either self-cancelled here (it saw
// READY on the recheck and never stops) or its gate entry was already visible
// when Go swept (and thus gets a SIGCONT). There is no interleaving in which a
// task is left frozen after the sweep has passed it.
static __always_inline int netns_gate(struct task_struct* task, __u32 netns_inum, __u32 ns_tid) {
    // Fast path: a proxy is already serving this namespace.
    struct proxy_state_key pkey = {.netns_inum = netns_inum};
    __u8* ready = bpf_map_lookup_elem(&proxy_state_map, &pkey);
    if (ready && *ready == PROXY_READY) {
        return 0;
    }

    // Compute the task's TID as seen from the witness PID namespace so that
    // userspace (which lives in the witness PID ns) can target it with kill().
    __u32 witness_tid = (__u32)bpf_get_current_pid_tgid();

    __u32 pid_ns = get_pid_ns_inum(task);
    if (pid_ns == witness_pid_ns_inum) {
        witness_tid = ns_tid;
    } else {
        struct pid* tp = BPF_CORE_READ(task, group_leader, thread_pid);
        if (tp) {
            __u32 key = 0;
            __u32* wlevel_ptr = bpf_map_lookup_elem(&witness_pid_ns_level_map, &key);
            if (wlevel_ptr) {
                unsigned int task_level = BPF_CORE_READ(tp, level);
                if (*wlevel_ptr <= task_level) {
                    witness_tid = BPF_CORE_READ(tp, numbers[*wlevel_ptr].nr);
                }
            }
        }
    }

    struct gate_key gkey = {
        .netns_inum = netns_inum,
        .tid = ns_tid,
    };
    struct gate_val gval = {
        .host_tid = witness_tid,
        .stop_ts_ns = bpf_ktime_get_ns(),
    };
    if (bpf_map_update_elem(&gate_map, &gkey, &gval, BPF_NOEXIST) != 0) {
        // An entry already exists for this task; it is (or will be) handled.
        return 0;
    }

    // RE-CHECK readiness now that our entry is visible to any sweep.
    ready = bpf_map_lookup_elem(&proxy_state_map, &pkey);
    if (ready && *ready == PROXY_READY) {
        // Userspace may have already finished sweeping, self-cancel so we do
        // not freeze a task no one will wake.
        bpf_map_delete_elem(&gate_map, &gkey);
        return 0;
    }

    // The entry is durably visible and the proxy is still not ready: freeze.
    DEBUG_LOG("netns_gate: SIGSTOP netns=%u ns_tid=%u", netns_inum, ns_tid);
    bpf_send_signal(SIGSTOP);

    return 0;
}

// gate_if_unready freezes the current task if it is authorized for interception
// and its network namespace has no ready proxy yet.
static __always_inline int gate_if_unready(void) {
    if (is_tracing_disabled()) {
        return 0;
    }

    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    __u32 pid_ns = get_pid_ns_inum(task);
    __u32 netns_inum = get_netns_inum(task);
    __u32 ns_tid = get_tid_ns(task);

    int authorized = 0;
    if (pid_ns == witness_pid_ns_inum) {
        if (is_witness_pid_ns_tid_allowed(ns_tid)) {
            authorized = 1;
        }
    } else if (is_pid_ns_tracked(pid_ns)) {
        authorized = 1;
    }

    if (!authorized) {
        return 0;
    }

    return netns_gate(task, netns_inum, ns_tid);
}

#endif /* __HELPERS_H__ */
