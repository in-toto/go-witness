// Copyright 2021 The Witness Contributors
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

//go:build linux && !amd64 && !arm64 && !arm && !386

package commandrun

import (
	"golang.org/x/sys/unix"
)

// Fallback syscall register decoding for Linux architectures that do not yet
// have architecture-specific ptrace register mappings.
func getSyscallId(regs unix.PtraceRegs) int {
	return -1
}

func getSyscallArgs(regs unix.PtraceRegs) []uintptr {
	return nil
}
