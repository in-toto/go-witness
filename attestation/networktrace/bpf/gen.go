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

//go:build linux

package bpf

// Generate BPF object files from C source using bpf2go.
// The generated files will contain Go bindings for loading the BPF programs and maps.
//
// Prerequisites:
// - clang and llvm installed
// - Linux kernel headers (vmlinux.h already provided in headers/)
// - bpf2go installed as a tool: go get -tool github.com/cilium/ebpf/cmd/bpf2go
//

//go:generate sh -c "go tool bpf2go -cc clang -target bpfel,bpfeb -go-package bpf -type orig_dst_key -type orig_dst_val -type orig_dst_key_v6 -type orig_dst_val_v6 -type pid_allowlist_key -type pid_allowlist_val -type comm_allowlist_key -type cgroup_allowlist_key -type tuple_key -type tuple_val -type tuple_key_v6 -type injection_time_val connect connect.bpf.c -- -I./headers -Wall -Werror $BPF_CFLAGS"
//go:generate sh -c "go tool bpf2go -cc clang -target bpfel,bpfeb -go-package bpf sockops sockops.bpf.c -- -I./headers -Wall -Werror $BPF_CFLAGS"
