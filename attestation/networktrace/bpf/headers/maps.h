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

#ifndef __MAPS_H__
#define __MAPS_H__

#define MAX_COMM_LEN 16

struct orig_dst_key {
    __u64 sock_cookie;
};

struct orig_dst_val {
    __u32 orig_ip;    // Original destination IP (IPv4)
    __u16 orig_port;  // Original destination port
    __u16 pad;
    __u64 cgroup_id;  // Cgroup ID
    __u32 pid;        // Process ID
    __u32 pad2;
    char comm[MAX_COMM_LEN];  // Process name
};

struct pid_allowlist_key {
    __u32 pid;
};

struct pid_allowlist_val {
    __u8 nested_allowed;  // whether nested children are also allowed (upto
                          // MAX_PARENT_WALK)
};

// Key for injection_time_map (single element, key is always 0)
struct injection_time_key {
    __u32 key;  // always 0
};

// Value storing when monitoring started (boot time in ns)
struct injection_time_val {
    __u64 injection_time;
};

struct comm_allowlist_key {
    char comm[MAX_COMM_LEN];
};

struct cgroup_allowlist_key {
    __u64 cgroup_id;
};

struct tuple_key {
    __u32 local_ip;
    __u16 local_port;
    __u16 pad1;
    __u32 remote_ip;
    __u16 remote_port;
    __u16 pad2;
};

struct tuple_val {
    __u64 client_cookie;  // Original client socket cookie from connect4
};

struct tuple_key_v6 {
    __u8 local_ip[16];
    __u16 local_port;
    __u16 pad1;
    __u8 remote_ip[16];
    __u16 remote_port;
    __u16 pad2;
};

struct orig_dst_key_v6 {
    __u64 sock_cookie;
};

struct orig_dst_val_v6 {
    __u8 orig_ip[16];  // IPv6 address
    __u16 orig_port;
    __u16 pad;
    __u32 pad1;
    __u64 cgroup_id;
    __u32 pid;
    __u32 pad2;
    char comm[MAX_COMM_LEN];  // Process name
};

#endif /* __MAPS_H__ */
