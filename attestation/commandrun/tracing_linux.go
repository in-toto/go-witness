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

//go:build linux

package commandrun

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"syscall"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/environment"
	"github.com/in-toto/go-witness/log"

	"golang.org/x/sys/unix"
)

const (
	MaxPathLen = 4096
)

// four signals that put a (multithreaded) process into group-stop:
// SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU.
// Per ptrace(2) "Group-stop": only these four signals are stopping signals, so
// if the tracer sees any other signal it cannot be a group-stop.
func isStoppingSignal(sig unix.Signal) bool {
	switch sig {
	case unix.SIGSTOP, unix.SIGTSTP, unix.SIGTTIN, unix.SIGTTOU:
		return true
	}
	return false
}

// waitAll wraps Wait4(-1, WALL) for a ptrace tracer's main loop.
// EINTR can be caused by some syscalls on restart, from ptrace(2)
// The excerpt:
//
//	however, kernel bugs exist which cause some system calls to fail
//	with EINTR even though no observable signal is injected to the
//	tracee.
//
// ECHILD is caused when waitAll is invoked but there are no more child processes.
// It's hard to reproduce this case, when trackedTIDs have a phantom TID that
// has already exited, but ignoring the error should not have any side effects.
// trackedTIDs might have some late deletions, but all threads are reaped and tracked.
func waitAll(status *unix.WaitStatus) (pid int, noChildren bool, err error) {
	for {
		pid, err = unix.Wait4(-1, status, unix.WALL, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.ECHILD) {
			return 0, true, nil
		}
		return pid, false, err
	}
}

type ptraceContext struct {
	traceePid           int
	mainProgram         string
	processes           map[int]*ProcessInfo
	exitCode            int
	hash                []cryptoutil.DigestValue
	environmentCapturer *environment.Capture

	executeHooks *attestation.ExecuteHooks
	hasPreExec   bool
}

func enableTracing(c *exec.Cmd) {
	if c.SysProcAttr == nil {
		c.SysProcAttr = &unix.SysProcAttr{}
	}
	c.SysProcAttr.Ptrace = true
}

func (rc *CommandRun) trace(c *exec.Cmd, actx *attestation.AttestationContext, hasPreExec bool) ([]ProcessInfo, error) {
	pctx := &ptraceContext{
		traceePid:           c.Process.Pid,
		mainProgram:         c.Path,
		processes:           make(map[int]*ProcessInfo),
		executeHooks:        rc.executeHooks,
		hasPreExec:          hasPreExec,
		hash:                actx.Hashes(),
		environmentCapturer: actx.EnvironmentCapturer(),
	}
	if err := pctx.runTrace(); err != nil {
		return nil, err
	}
	rc.ExitCode = pctx.exitCode
	if pctx.exitCode != 0 {
		return pctx.procInfoArray(), fmt.Errorf("exit status %v", pctx.exitCode)
	}
	return pctx.procInfoArray(), nil
}

// runWithPreExec uses ptrace only for the initial exec stop. It detaches before
// user code runs, unlocks the OS thread, and returns root-process waiting to
// os/exec so output copying and ProcessState remain consistent.
func (rc *CommandRun) runWithPreExec(c *exec.Cmd) error {
	runtime.LockOSThread()
	enableTracing(c)
	if err := c.Start(); err != nil {
		rc.executeHooks.AbortStage(attestation.StagePreExec, err)
		runtime.UnlockOSThread()
		return err
	}

	pctx := &ptraceContext{
		traceePid:    c.Process.Pid,
		executeHooks: rc.executeHooks,
		hasPreExec:   true,
	}
	if err := pctx.waitForPreExec(); err != nil {
		terminateStoppedTracee(c)
		runtime.UnlockOSThread()
		_ = c.Wait()
		return err
	}

	detachErr := unix.PtraceDetach(c.Process.Pid)
	if detachErr != nil && !errors.Is(detachErr, unix.ESRCH) {
		terminateStoppedTracee(c)
	}
	runtime.UnlockOSThread()

	waitErr := c.Wait()
	rc.ExitCode = exitCodeFromErr(waitErr, c)
	if detachErr != nil && !errors.Is(detachErr, unix.ESRCH) {
		return fmt.Errorf("detach ptrace after PreExec: %w", detachErr)
	}
	if rc.ExitCode != 0 {
		return fmt.Errorf("exit status %d", rc.ExitCode)
	}
	return waitErr
}

// exitCodeFromErr derives the shell-style exit code from an os/exec wait
// result: the exit status, or 128+signal for signal deaths, matching the
// ptrace backend's convention so all command-run modes report identically.
func exitCodeFromErr(err error, c *exec.Cmd) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return 128 + int(status.Signal())
		}
		return exitErr.ExitCode()
	}
	if c.ProcessState != nil {
		return c.ProcessState.ExitCode()
	}
	return 0
}

func terminateStoppedTracee(c *exec.Cmd) {
	if c.Process == nil {
		return
	}
	_ = ptraceDetachWithSignal(c.Process.Pid, int(unix.SIGKILL))
	_ = c.Process.Kill()
}

func (p *ptraceContext) waitForPreExec() error {
	var status unix.WaitStatus
	if _, err := unix.Wait4(p.traceePid, &status, 0, nil); err != nil {
		if p.hasPreExec {
			p.executeHooks.AbortStage(attestation.StagePreExec, err)
		}
		return err
	}
	if !status.Stopped() {
		err := fmt.Errorf("tracee %d did not stop at initial exec", p.traceePid)
		if p.hasPreExec {
			p.executeHooks.AbortStage(attestation.StagePreExec, err)
		}
		return err
	}
	if p.hasPreExec {
		log.Infof("Running PreExec hooks")
		if err := p.executeHooks.RunHooks(attestation.StagePreExec, p.traceePid); err != nil {
			return fmt.Errorf("PreExec hooks failed: %w", err)
		}
	}
	return nil
}

const seizeOptions = unix.PTRACE_O_TRACESYSGOOD |
	unix.PTRACE_O_TRACEEXEC |
	unix.PTRACE_O_TRACEVFORK |
	unix.PTRACE_O_TRACEFORK |
	unix.PTRACE_O_TRACECLONE

// transitionToSeize converts the tracee from the initial PTRACE_TRACEME
// attachment (which cannot use PTRACE_LISTEN) to a PTRACE_SEIZE attachment,
// which can. It must be called while the tracee is stopped at its initial
// execve trap , i.e. before any user code of the real command has run.
//
// There is no race, PTRACE_DETACH delivers a SIGSTOP as it detaches,
// leaving the tracee stopped, so the process can be PTRACE_SEIZEed.
// On return an interrupt is sent as seize can happen before/after the process
// ingests the SIGSTOP signal and all tasks enter a stopped state. If seize happens first
// and SIGSTOP is delivered post that, then the tracee enters a signal-delivery-stop. In that
// case interrupt is silently dropped by the kernel: (from manpage)
//
//	If any other ptrace-stop is generated at the same time
//	for example, if a signal is sent to the tracee), this ptrace-stop happens
func (p *ptraceContext) transitionToSeize() error {
	log.Debugf("(tracing) transitionToSeize: DETACH(SIGSTOP) pid=%d", p.traceePid)
	if err := ptraceDetachWithSignal(p.traceePid, int(unix.SIGSTOP)); err != nil {
		return fmt.Errorf("detach-with-SIGSTOP for seize handoff: %w", err)
	}
	log.Debugf("(tracing) transitionToSeize: SEIZE pid=%d", p.traceePid)
	if err := ptraceSeizeWithOptions(p.traceePid, uintptr(seizeOptions)); err != nil {
		return fmt.Errorf("ptrace seize: %w", err)
	}

	return nil
}

func (p *ptraceContext) runTrace() error {
	defer p.retryOpenedFiles()

	if err := p.waitForPreExec(); err != nil {
		return err
	}
	if err := p.transitionToSeize(); err != nil {
		return fmt.Errorf("transition to ptrace seize: %w", err)
	}

	procInfo := p.getProcInfo(p.traceePid)
	procInfo.Program = p.mainProgram

	var status unix.WaitStatus

	trackedTIDs := map[int]struct{}{p.traceePid: {}}
	seizeHandoff := true
	gateInjected := make(map[int]bool)
	gateParked := make(map[int]bool)

	if err := ptraceInterrupt(p.traceePid); err != nil {
		log.Debugf("(tracing) ptrace interrupt after seize: %v", err)
	}

	for len(trackedTIDs) > 0 { // Loop until all threads die
		pid, noChildren, err := waitAll(&status)
		if err != nil {
			return err
		}
		if noChildren {
			// The traced tree is gone (see waitAll); finish normally.
			break
		}

		// If a task in the kernel dies or exits, it reports death via Exited or Signaled other than the TGID in case of
		// execve(2) under ptrace. As in the man page:
		//   Note: the thread
		//     group leader does not report death via WIFEXITED(status) until
		//     there is at least one other live thread.  This eliminates the
		//     possibility that the tracer will see it dying and then
		//     reappearing.
		// It "may" (varies with kernel version) report direct Signaled with SIGKILL, but it is not guaranteed. So we need to track all threads and wait for them to die.
		// This is also required to reap the zombie threads and avoid leaving them in the process table.
		if status.Exited() || status.Signaled() {
			delete(trackedTIDs, pid)
			if pid == p.traceePid {
				if status.Exited() {
					p.exitCode = status.ExitStatus()
				} else if status.Signaled() {
					p.exitCode = 128 + int(status.Signal())
				}
			}
			continue
		}

		if status.Stopped() {
			sig := status.StopSignal()

			// Inject the signal back (e.g., SIGINT, SIGTERM, or Real SIGTRAP)
			injectedSig := int(sig)
			eventCode := (uint32(status) >> 16) & 0xFFFF

			if seizeHandoff && pid == p.traceePid &&
				eventCode == uint32(unix.PTRACE_EVENT_STOP) {
				seizeHandoff = false
				if err := unix.PtraceSyscall(pid, 0); err != nil {
					if errors.Is(err, unix.ESRCH) {
						delete(trackedTIDs, pid)
					} else {
						log.Debugf("(tracing) handoff PtraceSyscall failed: %v", err)
					}
				}
				continue
			}

			if sig == unix.SIGCONT && gateParked[pid] {
				delete(gateParked, pid)
				if err := unix.PtraceSyscall(pid, 0); err != nil && !errors.Is(err, unix.ESRCH) {
					log.Debugf("(tracing) gate resume failed: %v", err)
				} else if errors.Is(err, unix.ESRCH) {
					delete(trackedTIDs, pid)
				}
				continue
			}

			if sig == unix.SIGSTOP && eventCode == 0 && isGateSIGSTOP(pid) {
				gateInjected[pid] = true
				trackedTIDs[pid] = struct{}{}
				if err := unix.PtraceSyscall(pid, int(unix.SIGSTOP)); err != nil {
					if errors.Is(err, unix.ESRCH) {
						delete(trackedTIDs, pid)
						delete(gateInjected, pid)
					} else {
						log.Debugf("(tracing) gate inject failed: %v", err)
					}
				}
				continue
			}
			if sig == unix.SIGSTOP && eventCode == uint32(unix.PTRACE_EVENT_STOP) && gateInjected[pid] {
				delete(gateInjected, pid)
				if err := ptraceListen(pid); err == nil {
					gateParked[pid] = true
					trackedTIDs[pid] = struct{}{}
					continue
				}
				log.Debugf("(tracing) gate LISTEN failed pid=%d: %v", pid, err)
			}

			// Distinguish the 3 types of traps
			// since we set PTRACE_O_TRACESYSGOOD any traps triggered by ptrace will have its signal set to SIGTRAP|0x80.
			// If we catch a signal that isn't a ptrace'd signal we want to let the process continue to handle that signal, so we inject the thrown signal back to the process.
			// If it was a ptrace SIGTRAP we suppress the signal and send 0
			isSyscallTrap := sig == (unix.SIGTRAP | 0x80)
			isRegularTrap := sig == unix.SIGTRAP

			if isStoppingSignal(sig) {
				injectedSig = 0
				trackedTIDs[pid] = struct{}{}
			}

			if isSyscallTrap {
				injectedSig = 0
				if err := p.nextSyscall(pid); err != nil {
					log.Debugf("(tracing) processing syscall: %v", err)
				}
			} else if isRegularTrap {
				// PTRACE_EVENT stops also come as regular SIGTRAP irrespective of TRACESYSGOOD
				// eventCode is in the high bits of the status

				if eventCode != 0 {
					// Ptrace fork/clone/exec event: suppress the synthetic trap.
					injectedSig = 0

					switch eventCode {
					case unix.PTRACE_EVENT_CLONE, unix.PTRACE_EVENT_FORK, unix.PTRACE_EVENT_VFORK:
						newTIDMsg, _ := unix.PtraceGetEventMsg(pid)
						newTID := int(newTIDMsg)
						if _, known := trackedTIDs[newTID]; !known {
							trackedTIDs[newTID] = struct{}{}
						}
					case unix.PTRACE_EVENT_EXEC:
						oldTID, err := unix.PtraceGetEventMsg(pid)
						if err == nil {
							delete(trackedTIDs, int(oldTID))
						}
						trackedTIDs[pid] = struct{}{}

					}
				}
			}

			if err := unix.PtraceSyscall(pid, injectedSig); err != nil {
				// The tracee may have died while stopped; ESRCH means it is
				// gone, so drop it and keep reaping the remaining threads
				// instead of abandoning the wait loop.
				if errors.Is(err, unix.ESRCH) {
					delete(trackedTIDs, pid)
				} else {
					log.Debugf("(tracing) ptrace syscall error: %v", err)
				}
			}
		} else {
			if err := unix.PtraceSyscall(pid, 0); err != nil {
				if errors.Is(err, unix.ESRCH) {
					delete(trackedTIDs, pid)
				} else {
					log.Debugf("(tracing) got error from ptrace syscall: %v", err)
				}
			}
		}
	}

	// A task killed while sitting in a ptrace stop (e.g. an external SIGKILL)
	// leaves no resumable stop: the resume above returned ESRCH, the TID was
	// dropped, and the task's death report (WIFEXITED/WIFSIGNALED) has not
	// been waited for yet. Reap whatever is left so the root's real exit
	// status is not lost and no traced child lingers as a zombie.
	p.reapRemainingTasks()
	return nil
}

// reapRemainingTasks waits for every remaining traced child until ECHILD. A
// status for the root tracee captured here (missed by the main loop because
// the task died inside a ptrace stop) updates the recorded exit code.
func (p *ptraceContext) reapRemainingTasks() {
	for {
		var status unix.WaitStatus
		w, err := unix.Wait4(-1, &status, unix.WALL, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.ECHILD) || w <= 0 {
			return
		}
		if w == p.traceePid {
			switch {
			case status.Exited():
				p.exitCode = status.ExitStatus()
			case status.Signaled():
				p.exitCode = 128 + int(status.Signal())
			}
		}
		log.Debugf("(tracing) final reap pid=%d exited=%v signaled=%v code=%d",
			w, status.Exited(), status.Signaled(), p.exitCode)
	}
}

func (p *ptraceContext) retryOpenedFiles() {
	// after tracing, look through opened files to try to resolve any newly created files
	for _, procInfo := range p.processes {
		for file, digestSet := range procInfo.OpenedFiles {
			if digestSet != nil {
				continue
			}

			newDigest, err := cryptoutil.CalculateDigestSetFromFile(file, p.hash)

			if err != nil {
				delete(procInfo.OpenedFiles, file)
				continue
			}

			procInfo.OpenedFiles[file] = newDigest
		}
	}
}

func (p *ptraceContext) nextSyscall(pid int) error {
	regs := unix.PtraceRegs{}
	if err := unix.PtraceGetRegs(pid, &regs); err != nil {
		return err
	}

	msg, err := unix.PtraceGetEventMsg(pid)
	if err != nil {
		return err
	}

	if msg == unix.PTRACE_EVENTMSG_SYSCALL_ENTRY {
		if err := p.handleSyscall(pid, regs); err != nil {
			return err
		}
	}

	return nil
}

func (p *ptraceContext) handleSyscall(pid int, regs unix.PtraceRegs) error {
	argArray := getSyscallArgs(regs)
	syscallId := getSyscallId(regs)

	switch syscallId {
	case unix.SYS_EXECVE:
		procInfo := p.getProcInfo(pid)

		program, err := p.readSyscallReg(pid, argArray[0], MaxPathLen)
		if err == nil {
			procInfo.Program = program
		}

		exeLocation := fmt.Sprintf("/proc/%d/exe", procInfo.ProcessID)
		commLocation := fmt.Sprintf("/proc/%d/comm", procInfo.ProcessID)
		envinLocation := fmt.Sprintf("/proc/%d/environ", procInfo.ProcessID)
		cmdlineLocation := fmt.Sprintf("/proc/%d/cmdline", procInfo.ProcessID)
		status := fmt.Sprintf("/proc/%d/status", procInfo.ProcessID)

		// read status file and set attributes on success
		statusFile, err := os.ReadFile(status)
		if err == nil {
			procInfo.SpecBypassIsVuln = getSpecBypassIsVulnFromStatus(statusFile)
			ppid, err := getPPIDFromStatus(statusFile)
			if err == nil {
				procInfo.ParentPID = ppid
			}
		}

		comm, err := os.ReadFile(commLocation)
		if err == nil {
			procInfo.Comm = cleanString(string(comm))
		}

		environ, err := os.ReadFile(envinLocation)
		if err == nil {
			allVars := strings.Split(string(environ), "\x00")

			env := make([]string, 0)
			capturedEnv := p.environmentCapturer.Capture(allVars)
			for k, v := range capturedEnv {
				env = append(env, fmt.Sprintf("%s=%s", k, v))
			}

			procInfo.Environ = strings.Join(env, " ")
		}

		cmdline, err := os.ReadFile(cmdlineLocation)
		if err == nil {
			procInfo.Cmdline = cleanString(string(cmdline))
		}

		exeDigest, err := cryptoutil.CalculateDigestSetFromFile(exeLocation, p.hash)
		if err == nil {
			procInfo.ExeDigest = exeDigest
		}

		if program != "" {
			programDigest, err := cryptoutil.CalculateDigestSetFromFile(program, p.hash)
			if err == nil {
				procInfo.ProgramDigest = programDigest
			}

		}

	case unix.SYS_OPENAT:
		file, err := p.readSyscallReg(pid, argArray[1], MaxPathLen)
		if err != nil {
			return err
		}

		procInfo := p.getProcInfo(pid)
		digestSet, err := cryptoutil.CalculateDigestSetFromFile(file, p.hash)
		if err != nil {
			if _, isPathErr := err.(*os.PathError); isPathErr {
				procInfo.OpenedFiles[file] = nil
			}

			return err
		}

		procInfo.OpenedFiles[file] = digestSet
	}

	return nil
}

func (ctx *ptraceContext) getProcInfo(pid int) *ProcessInfo {
	procInfo, ok := ctx.processes[pid]
	if !ok {
		procInfo = &ProcessInfo{
			ProcessID:   pid,
			OpenedFiles: make(map[string]cryptoutil.DigestSet),
		}

		ctx.processes[pid] = procInfo
	}

	return procInfo
}

func (ctx *ptraceContext) procInfoArray() []ProcessInfo {
	processes := make([]ProcessInfo, 0)
	for _, procInfo := range ctx.processes {
		processes = append(processes, *procInfo)
	}

	return processes
}

func (ctx *ptraceContext) readSyscallReg(pid int, addr uintptr, n int) (string, error) {
	data := make([]byte, n)
	localIov := unix.Iovec{
		Base: &data[0],
	}
	localIov.SetLen(n)

	removeIov := unix.RemoteIovec{
		Base: addr,
		Len:  n,
	}

	// ProcessVMReadv is much faster than PtracePeekData since it doesn't route the data through kernel space,
	// but there may be times where this doesn't work.  We may want to fall back to PtracePeekData if this fails
	numBytes, err := unix.ProcessVMReadv(pid, []unix.Iovec{localIov}, []unix.RemoteIovec{removeIov}, 0)
	if err != nil {
		return "", err
	}

	if numBytes == 0 {
		return "", nil
	}

	// don't want to use cgo... look for the first 0 byte for the end of the c string
	size := bytes.IndexByte(data, 0)
	return string(data[:size]), nil
}

func cleanString(s string) string {
	return strings.TrimSpace(strings.ReplaceAll(s, "\x00", " "))
}

func getPPIDFromStatus(status []byte) (int, error) {
	statusStr := string(status)
	lines := strings.Split(statusStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "PPid:") {
			parts := strings.Split(line, ":")
			ppid := strings.TrimSpace(parts[1])
			return strconv.Atoi(ppid)
		}
	}

	return 0, nil
}

func getSpecBypassIsVulnFromStatus(status []byte) bool {
	statusStr := string(status)
	lines := strings.Split(statusStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Speculation_Store_Bypass:") {
			parts := strings.Split(line, ":")
			isVuln := strings.TrimSpace(parts[1])
			if strings.Contains(isVuln, "vulnerable") {
				return true
			}
		}
	}

	return false
}
