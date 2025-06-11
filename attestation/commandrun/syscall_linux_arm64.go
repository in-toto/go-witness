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

//go:build linux && arm64

package commandrun

import (
	"golang.org/x/sys/unix"
)

func getRegisters() *syscallRegisters {
	return &unix.PtraceRegs{}
}

func getSyscallID(regs *syscallRegisters) uint64 {
	return uint64(regs.Regs[8])
}

func getArg0(regs *syscallRegisters) uintptr {
	return uintptr(regs.Regs[0])
}

func getArg1(regs *syscallRegisters) uintptr {
	return uintptr(regs.Regs[1])
}

func getArg2(regs *syscallRegisters) uintptr {
	return uintptr(regs.Regs[2])
}

func getArg3(regs *syscallRegisters) uintptr {
	return uintptr(regs.Regs[3])
}

func getArg4(regs *syscallRegisters) uintptr {
	return uintptr(regs.Regs[4])
}

func getArg5(regs *syscallRegisters) uintptr {
	return uintptr(regs.Regs[5])
}

func getSyscallReturn(regs *syscallRegisters) int64 {
	return int64(regs.Regs[0])
}