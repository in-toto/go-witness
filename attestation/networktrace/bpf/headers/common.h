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

#ifndef SIGSTOP
#define SIGSTOP 19
#endif

// Default Proxy configuration
// Userspace can override the volatile variables
#define PROXY_PORT_TCP 8888
#define PROXY_IP 0x0100007F  // 127.0.0.1 in network byte order (big endian)

#define PROXY_NOT_READY 0
#define PROXY_READY 1

#define LIFECYCLE_NOT_STARTED 0
#define LIFECYCLE_RUNNING 1
#define LIFECYCLE_TRANSITIONING 2
#define LIFECYCLE_EXITED 3
#define LIFECYCLE_FAILED 4

#define LIFECYCLE_ERROR_NONE 0
#define LIFECYCLE_ERROR_TASK_IDENTITY 1
#define LIFECYCLE_ERROR_TASK_INSERT 2
#define LIFECYCLE_ERROR_EXEC_MIGRATION 3
#define LIFECYCLE_ERROR_COUNTER_UNDERFLOW 4
#define LIFECYCLE_ERROR_MAP_UPDATE 5

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
