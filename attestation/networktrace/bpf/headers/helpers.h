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

static __always_inline int is_tid_allowed(__u32 tid) {
    struct tid_allowlist_key key = {
        .tid = tid,
    };

    struct tid_allowlist_val* val = bpf_map_lookup_elem(&tid_allowlist, &key);
    if (val) return 1;

    return 0;
}

static __always_inline int should_intercept(__u32 tid, __u64 cgroup_id,
                                            const char* comm) {
    DEBUG_LOG("should_intercept: ENTER tid=%d cgroup=%llu comm=%s", tid, cgroup_id, comm);

    if (is_tid_allowed(tid)) {
        DEBUG_LOG("should_intercept: ALLOWED tid=%d (tid_allowlist)", tid);
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

    DEBUG_LOG("should_intercept: DENIED tid=%d cgroup=%llu comm=%s", tid, cgroup_id, comm);
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
