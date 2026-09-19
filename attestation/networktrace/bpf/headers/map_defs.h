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

#ifndef __MAP_DEFS_H__
#define __MAP_DEFS_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "maps.h"


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct orig_dst_key);
    __type(value, struct orig_dst_val);
} orig_dst_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct orig_dst_key_v6);
    __type(value, struct orig_dst_val_v6);
} orig_dst_map_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct witness_pid_ns_tid_key);
    __type(value, struct witness_pid_ns_tid_val);
} witness_pid_ns_tid_allowlist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // Global Host TID
    __type(value, __u32); // Namespace-aware TID
} pending_execs SEC(".maps");

// Per-namespace proxy readiness latch (userspace = sole writer, monotonic).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct proxy_state_key);
    __type(value, __u8);  // 0 = not ready, 1 = PROXY_READY
} proxy_state_map SEC(".maps");

// Durable SIGSTOP gate / proxy-request queue.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct gate_key);
    __type(value, struct gate_val);
} gate_map SEC(".maps");

// Single-element kill switch (userspace = sole writer).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct control_val);
} control_map SEC(".maps");

// Cached absolute level of the witness PID namespace. Written once by the
// execve gate when it first encounters a witness-PID-ns process, then read
// by all descendant invocations to directly index thread_pid.numbers[] for
// the witness-ns TID (avoids a bounded ancestor-chain loop).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} witness_pid_ns_level_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct comm_allowlist_key);
    __type(value, __u8);
} comm_allowlist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct cgroup_allowlist_key);
    __type(value, __u8);
} cgroup_allowlist SEC(".maps");

// 4-tuple to client cookie mapping (IPv4)
// Used to link server (accepted) socket cookies to original client cookies
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct tuple_key);
    __type(value, struct tuple_val);
} tuple_to_cookie_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct tuple_key_v6);
    __type(value, struct tuple_val);
} tuple_to_cookie_map_v6 SEC(".maps");

// PID namespaces created by tracked processes (via CLONE_NEWPID). An entry
// means the entire PID namespace is whitelisted, all traffic from any
// process in that namespace is intercepted unconditionally, regardless of
// TID, comm, or cgroup.
// If a new process is created in a PID ns using setns(), that complete PID namespace
// is whitelisted instead of just that process. This simplification is acceptable as the
// pattern to spawn a new process in an existing PID namespace during a build (which is not meant to be tracked)
// is uncommon. 
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);  // PID namespace inode
    __type(value, __u8);
} tracked_pid_ns_map SEC(".maps");

#endif /* __MAP_DEFS_H__ */
