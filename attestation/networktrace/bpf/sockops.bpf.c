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

volatile const __u32 host_netns_inum = 0;  // to be set from user-space

SEC("sockops")
int tcp_sockops(struct bpf_sock_ops* skops) {
    __u32 op = skops->op;

    if (op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB &&
        op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        return 1;
    }

    // Get comm from task_struct manually
    char comm[MAX_COMM_LEN] = {0};
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    if (task) {
        BPF_CORE_READ_STR_INTO(&comm, task, comm);
    }

    struct bpf_sock* sk = skops->sk;
    if (sk != NULL) {
        if (sk->type != SOCK_STREAM) {
            return 1;
        }
    }

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 cgroup_id = bpf_get_current_cgroup_id();


    int intercept_result = should_intercept(pid, cgroup_id, comm);
    if (!intercept_result) {
        return 1;
    }
    __u32 netns_inum = get_netns_inum(task);
    if (host_netns_inum != 0 && netns_inum != host_netns_inum) {
        // Not in the host network namespace
        DEBUG_LOG("sockops: SKIP diff-netns pid=%d comm=%s", pid, comm);
        return 1;
    }

    __u64 cookie = bpf_get_socket_cookie(skops);

    switch (op) {
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: {
            // Client socket established (connect() succeeded)
            __u32 family = skops->family;

            if (family == AF_INET) {
                // Store 4-tuple -> client cookie mapping
                // This allows us to link the server (accepted) socket to this
                // client socket
                struct tuple_key tkey = {
                    .local_ip = skops->local_ip4,
                    .local_port = skops->local_port,
                    .remote_ip = skops->remote_ip4,
                    .remote_port = bpf_ntohl(skops->remote_port),
                };
                struct tuple_val tval = {
                    .client_cookie = cookie,
                };
                int ret = bpf_map_update_elem(&tuple_to_cookie_map, &tkey,
                                              &tval, BPF_ANY);

                if (ret < 0) {
                    LOG("sockops: ERROR ACTIVE_EST map_update pid=%d ret=%d",
                        pid, ret);
                } else {
                    LOG("sockops: ACTIVE_EST pid=%d comm=%s dst=%x:%d", pid,
                        comm, tkey.remote_ip, tkey.remote_port);
                }
            } else if (family == AF_INET6) {
                // Store 4-tuple -> client cookie mapping (IPv6)
                struct tuple_key_v6 tkey = {
                    .local_port = skops->local_port,
                    .remote_port = bpf_ntohl(skops->remote_port),
                };
                // Copy IPv6 addresses element-by-element
                ((__u32*)tkey.local_ip)[0] = skops->local_ip6[0];
                ((__u32*)tkey.local_ip)[1] = skops->local_ip6[1];
                ((__u32*)tkey.local_ip)[2] = skops->local_ip6[2];
                ((__u32*)tkey.local_ip)[3] = skops->local_ip6[3];

                ((__u32*)tkey.remote_ip)[0] = skops->remote_ip6[0];
                ((__u32*)tkey.remote_ip)[1] = skops->remote_ip6[1];
                ((__u32*)tkey.remote_ip)[2] = skops->remote_ip6[2];
                ((__u32*)tkey.remote_ip)[3] = skops->remote_ip6[3];

                struct tuple_val tval = {
                    .client_cookie = cookie,
                };
                int ret = bpf_map_update_elem(&tuple_to_cookie_map_v6, &tkey,
                                              &tval, BPF_ANY);

                if (ret < 0) {
                    LOG("sockops: ERROR ACTIVE_EST v6 map_update pid=%d ret=%d",
                        pid, ret);
                } else {
                    LOG("sockops: ACTIVE_EST v6 pid=%d comm=%s port=%d", pid,
                        comm, tkey.remote_port);
                }
            }

            break;
        }

        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: {
            // Server socket established (accept() succeeded)
            // This is the proxy's accepted socket - we need to link it to the
            // client cookie
            __u64 server_cookie = bpf_get_socket_cookie(skops);
            __u32 family = skops->family;

            if (family == AF_INET) {
                // Build the 4-tuple (same as client, but from server
                // perspective) Note: local/remote are swapped from client's
                // perspective
                struct tuple_key tkey = {
                    .local_ip =
                        skops->remote_ip4,  // Client's IP (from server's view,
                                            // this is remote)
                    .local_port =
                        bpf_ntohl(skops->remote_port),  // Client's port
                    .remote_ip = skops->local_ip4,  // Proxy's IP (from server's
                                                    // view, this is local)
                    .remote_port = skops->local_port,  // Proxy's port
                };

                // Lookup the client cookie using the 4-tuple
                struct tuple_val* tval =
                    bpf_map_lookup_elem(&tuple_to_cookie_map, &tkey);
                if (tval) {
                    __u64 client_cookie = tval->client_cookie;

                    // Lookup the original destination info from client cookie
                    struct orig_dst_key orig_key = {.sock_cookie =
                                                        client_cookie};
                    struct orig_dst_val* orig_val =
                        bpf_map_lookup_elem(&orig_dst_map, &orig_key);

                    if (orig_val) {
                        // Store the orig_dst info under the SERVER cookie
                        // This allows userspace to lookup using the accepted
                        // socket's cookie
                        struct orig_dst_key server_key = {.sock_cookie =
                                                              server_cookie};
                        int ret = bpf_map_update_elem(
                            &orig_dst_map, &server_key, orig_val, BPF_ANY);

                        if (ret < 0) {
                            LOG("sockops: ERROR PASSIVE_EST map_update pid=%d "
                                "ret=%d",
                                pid, ret);
                        } else {
                            LOG("sockops: PASSIVE_EST LINKED pid=%d dst=%x:%d",
                                pid, orig_val->orig_ip, orig_val->orig_port);
                        }
                    } else {
                        DEBUG_LOG(
                            "sockops: WARN PASSIVE_EST no orig_dst cookie=%llu",
                            client_cookie);
                    }
                } else {
                    DEBUG_LOG("sockops: WARN PASSIVE_EST no tuple match pid=%d",
                              pid);
                }
            } else if (family == AF_INET6) {
                // Build the 4-tuple (IPv6)
                struct tuple_key_v6 tkey = {
                    .local_port =
                        bpf_ntohl(skops->remote_port),  // Client's port
                    .remote_port = skops->local_port,   // Proxy's port
                };

                // Copy IPv6 addresses (swapped client/server perspective)
                ((__u32*)tkey.local_ip)[0] = skops->remote_ip6[0];  // Client IP
                ((__u32*)tkey.local_ip)[1] = skops->remote_ip6[1];
                ((__u32*)tkey.local_ip)[2] = skops->remote_ip6[2];
                ((__u32*)tkey.local_ip)[3] = skops->remote_ip6[3];

                ((__u32*)tkey.remote_ip)[0] = skops->local_ip6[0];  // Proxy IP
                ((__u32*)tkey.remote_ip)[1] = skops->local_ip6[1];
                ((__u32*)tkey.remote_ip)[2] = skops->local_ip6[2];
                ((__u32*)tkey.remote_ip)[3] = skops->local_ip6[3];

                // Lookup the client cookie using the 4-tuple
                struct tuple_val* tval =
                    bpf_map_lookup_elem(&tuple_to_cookie_map_v6, &tkey);
                if (tval) {
                    __u64 client_cookie = tval->client_cookie;

                    // Lookup the original destination info from client cookie
                    struct orig_dst_key_v6 orig_key = {.sock_cookie =
                                                           client_cookie};
                    struct orig_dst_val_v6* orig_val =
                        bpf_map_lookup_elem(&orig_dst_map_v6, &orig_key);

                    if (orig_val) {
                        // Store the orig_dst info under the SERVER cookie
                        struct orig_dst_key_v6 server_key = {.sock_cookie =
                                                                 server_cookie};
                        int ret = bpf_map_update_elem(
                            &orig_dst_map_v6, &server_key, orig_val, BPF_ANY);

                        if (ret < 0) {
                            LOG("sockops: ERROR PASSIVE_EST v6 map_update "
                                "pid=%d ret=%d",
                                pid, ret);
                        } else {
                            LOG("sockops: PASSIVE_EST v6 LINKED pid=%d port=%d",
                                pid, orig_val->orig_port);
                        }
                    } else {
                        DEBUG_LOG(
                            "sockops: WARN PASSIVE_EST v6 no orig_dst "
                            "cookie=%llu",
                            client_cookie);
                    }
                } else {
                    DEBUG_LOG(
                        "sockops: WARN PASSIVE_EST v6 no tuple match pid=%d",
                        pid);
                }
            }

            break;
        }

        default:
            break;
    }

    return 1;
}
