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

#include "maps.h"

// LIBBPF_PIN_BY_NAME enables the cilium/ebpf library to automatically
// pin and reuse maps based on MapOptions.PinPath
#define LIBBPF_PIN_BY_NAME 1

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, struct orig_dst_key);
    __type(value, struct orig_dst_val);
} orig_dst_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, struct orig_dst_key_v6);
    __type(value, struct orig_dst_val_v6);
} orig_dst_map_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, struct pid_allowlist_key);
    __type(value, struct pid_allowlist_val);
} pid_allowlist SEC(".maps");

// Single-element map storing when monitoring started (boot time in ns).
// Used to reject processes that reused a PID after monitoring began.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, __u32);
    __type(value, struct injection_time_val);
} injection_time_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, struct comm_allowlist_key);
    __type(value, __u8);
} comm_allowlist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, struct cgroup_allowlist_key);
    __type(value, __u8);
} cgroup_allowlist SEC(".maps");

// 4-tuple to client cookie mapping (IPv4)
// Used to link server (accepted) socket cookies to original client cookies
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, struct tuple_key);
    __type(value, struct tuple_val);
} tuple_to_cookie_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, struct tuple_key_v6);
    __type(value, struct tuple_val);
} tuple_to_cookie_map_v6 SEC(".maps");

#endif /* __MAP_DEFS_H__ */
