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

package commandrun

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// From Kernel source code v7.1.2
//
//	/*
//	* si_code values
//	* Digital reserves positive values for kernel-generated signals.
//	*/
//	#define SI_USER		0		/* sent by kill, sigsend, raise */
//	#define SI_KERNEL	0x80		/* sent by the kernel from somewhere */
//	#define SI_QUEUE	-1		/* sent by sigqueue */
//	#define SI_TIMER	-2		/* sent by timer expiration */
//	#define SI_MESGQ	-3		/* sent by real time mesq state change */
//	#define SI_ASYNCIO	-4		/* sent by AIO completion */
//	#define SI_SIGIO	-5		/* sent by queued SIGIO */
//	#define SI_TKILL	-6		/* sent by tkill system call */
//	#define SI_DETHREAD	-7		/* sent by execve() killing subsidiary threads */
//	#define SI_ASYNCNL	-60		/* sent by glibc async name lookup completion */
const (
	siCodeKernel = 0x80 // SI_KERNEL: bpf_send_signal and other kernel-raised signals
)

// ptraceGetSigInfo retrieves the siginfo_t for the signal that caused the
// current ptrace stop. x/sys/unix defines PTRACE_GETSIGINFO and the Siginfo
// type but does not provide a wrapper, so we issue the raw ptrace syscall.
//
// Returns an error (EINVAL) when the tracee is in a group-stop rather than a
// signal-delivery-stop.
func ptraceGetSigInfo(pid int) (*unix.Siginfo, error) {
	var si unix.Siginfo
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, uintptr(unix.PTRACE_GETSIGINFO),
		uintptr(pid), 0, uintptr(unsafe.Pointer(&si)), 0, 0)
	if errno != 0 {
		return nil, errno
	}
	return &si, nil
}

// isGateSIGSTOP reports whether the stopping-signal stop the tracee is
// currently in was caused by a SIGSTOP that our BPF gate raised via
// bpf_send_signal (si_code == SI_KERNEL).
//
// This distinguishes the gate's SIGSTOP from:
//   - the auto-attach SIGSTOP of a fork/vfork/clone child (SI_USER),
//   - an explicit kill(2) SIGSTOP (SI_USER),
//   - a self-inflicted raise()/tgkill stop (SI_TKILL),
//   - a group-stop (PTRACE_GETSIGINFO -> EINVAL).
func isGateSIGSTOP(pid int) bool {
	si, err := ptraceGetSigInfo(pid)
	if err != nil {
		// Group-stop (EINVAL) or the task vanished: not our gate SIGSTOP.
		return false
	}
	return si.Code == siCodeKernel
}

func ptraceRaw(request, pid int, addr, data uintptr) error {
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, uintptr(request), uintptr(pid), addr, data, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func ptraceSeizeWithOptions(pid int, options uintptr) error {
	return ptraceRaw(unix.PTRACE_SEIZE, pid, 0, options)
}

func ptraceListen(pid int) error {
	return ptraceRaw(unix.PTRACE_LISTEN, pid, 0, 0)
}

func ptraceInterrupt(pid int) error {
	return ptraceRaw(unix.PTRACE_INTERRUPT, pid, 0, 0)
}

func ptraceDetachWithSignal(pid, sig int) error {
	return ptraceRaw(unix.PTRACE_DETACH, pid, 0, uintptr(sig))
}
