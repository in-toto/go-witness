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

//go:generate sh -c "go tool bpf2go -cc clang -no-strip -target bpfel,bpfeb -go-package bpf filetraceSyscall filetrace_syscall.bpf.c -- -Wall -Werror -I ../../bpf-common/headers $BPF_CFLAGS"

// -I \"$(go env GOPATH)/pkg/mod/github.com/cilium/ebpf@$(go list -m -f '{{.Version}}' github.com/cilium/ebpf)/examples/headers\"
