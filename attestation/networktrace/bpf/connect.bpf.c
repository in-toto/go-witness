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
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "headers/common.h"
#include "headers/helpers.h"
#include "headers/map_defs.h"
#include "headers/maps.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

volatile const __u32 proxy_port = PROXY_PORT_TCP;
volatile const __u32 proxy_ip = PROXY_IP;
volatile const __u32 host_netns_inum = 0;  // to be set from user-space

SEC("cgroup/connect4")
int intercept_connect4(struct bpf_sock_addr* ctx) {
    // Only intercept TCP (SOCK_STREAM)
    if (ctx->type != SOCK_STREAM) {
        return 1;  // Allow UDP, raw, etc. to proceed without redirect
    }

    __u64 cookie = bpf_get_socket_cookie(ctx);
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    char comm[MAX_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    int should_intercept_result = should_intercept(pid, cgroup_id, comm);

    if (!should_intercept_result) {
        return 1;
    }

    __u16 dest_port = bpf_ntohs(ctx->user_port);
    __u32 dest_ip = ctx->user_ip4;

    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    __u32 netns_inum = get_netns_inum(task);

    if (netns_inum != host_netns_inum) {
        // Not in host netns, skip interception
        DEBUG_LOG("connect4: SKIP diff-netns pid=%d comm=%s", pid, comm);
        return 1;
    }

    if (dest_port == 53) {
        // DNS traffic - skip interception but log in debug mode
        DEBUG_LOG("connect4: SKIP DNS pid=%d comm=%s", pid, comm);
        return 1;
    }

    struct orig_dst_key orig_key = {.sock_cookie = cookie};
    struct orig_dst_val orig_val = {
        .orig_ip = dest_ip,
        .orig_port = dest_port,
        .cgroup_id = cgroup_id,
        .pid = pid,
    };
    __builtin_memcpy(orig_val.comm, comm, MAX_COMM_LEN);

    int ret = bpf_map_update_elem(&orig_dst_map, &orig_key, &orig_val, BPF_ANY);
    if (ret < 0) {
        LOG("connect4: ERROR map_update pid=%d ret=%d", pid, ret);
        return 1;
    }

    // Redirect to local proxy (using volatile variables set by userspace)
    ctx->user_ip4 = bpf_htonl(proxy_ip);
    ctx->user_port = bpf_htons(proxy_port);

    LOG("connect4: INTERCEPT pid=%d comm=%s dst=%x:%d", pid, comm, dest_ip,
        dest_port);

    return 1;
}

SEC("cgroup/connect6")
int intercept_connect6(struct bpf_sock_addr* ctx) {
    // Only intercept TCP (SOCK_STREAM)
    if (ctx->type != SOCK_STREAM) {
        return 1;  // Allow UDP, raw, etc. to proceed without redirect
    }

    __u64 cookie = bpf_get_socket_cookie(ctx);
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    char comm[MAX_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    int should_intercept_result = should_intercept(pid, cgroup_id, comm);

    if (!should_intercept_result) {
        return 1;
    }

    __u16 dest_port = bpf_ntohs(ctx->user_port);

    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    __u32 netns_inum = get_netns_inum(task);

    if (netns_inum != host_netns_inum) {
        // Not in host netns, skip interception
        DEBUG_LOG("connect6: SKIP diff-netns pid=%d comm=%s", pid, comm);
        return 1;
    }

    if (dest_port == 53) {
        // DNS traffic - skip interception but log in debug mode
        DEBUG_LOG("connect6: SKIP DNS pid=%d comm=%s", pid, comm);
        return 1;  // Allow DNS to proceed unintercepted (no redirection)
    }

    struct orig_dst_key_v6 orig_key = {.sock_cookie = cookie};
    struct orig_dst_val_v6 orig_val = {
        .orig_port = dest_port,
        .cgroup_id = cgroup_id,
        .pid = pid,
    };

    // Copy IPv6 address - manual unroll to make bpf verifier happy
    ((__u32*)orig_val.orig_ip)[0] = ctx->user_ip6[0];
    ((__u32*)orig_val.orig_ip)[1] = ctx->user_ip6[1];
    ((__u32*)orig_val.orig_ip)[2] = ctx->user_ip6[2];
    ((__u32*)orig_val.orig_ip)[3] = ctx->user_ip6[3];

    __builtin_memcpy(orig_val.comm, comm, MAX_COMM_LEN);

    int ret =
        bpf_map_update_elem(&orig_dst_map_v6, &orig_key, &orig_val, BPF_ANY);
    if (ret < 0) {
        LOG("connect6: ERROR map_update pid=%d ret=%d", pid, ret);
        return 1;
    }

    // Redirect to local proxy (IPv6 loopback ::1)
    ctx->user_ip6[0] = 0;
    ctx->user_ip6[1] = 0;
    ctx->user_ip6[2] = 0;
    ctx->user_ip6[3] = bpf_htonl(1);  // ::1 in network byte order
    ctx->user_port = bpf_htons(proxy_port);

    LOG("connect6: INTERCEPT pid=%d comm=%s port=%d", pid, comm, dest_port);

    return 1;
}
