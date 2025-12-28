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

#ifndef __COMMON_H__
#define __COMMON_H__

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifndef SOCK_STREAM
#define SOCK_STREAM 1
#endif
#ifndef SOCK_DGRAM
#define SOCK_DGRAM 2
#endif

// Default Proxy configuration
// Userspace can override the volatile variables
#define PROXY_PORT_TCP 8888
#define PROXY_IP 0x0100007F  // 127.0.0.1 in network byte order (big endian)

#define LOG(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)

// Debug logging
#ifdef BPF_DEBUG
#define DEBUG_LOG(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define DEBUG_LOG(fmt, ...) \
    do {                    \
    } while (0)
#endif

#endif /* __COMMON_H__ */
