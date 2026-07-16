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
	"strconv"
	"strings"

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

func signalName(sig unix.Signal) string {
	switch sig {
	case unix.SIGSTOP:
		return "SIGSTOP"
	case unix.SIGCONT:
		return "SIGCONT"
	case unix.SIGTRAP:
		return "SIGTRAP"
	case unix.SIGCHLD:
		return "SIGCHLD"
	case unix.SIGKILL:
		return "SIGKILL"
	case unix.SIGTERM:
		return "SIGTERM"
	case unix.SIGALRM:
		return "SIGALRM"
	default:
		return fmt.Sprintf("sig=%d", int(sig))
	}
}

func ptraceEventName(ev uint32) string {
	switch ev {
	case uint32(unix.PTRACE_EVENT_STOP):
		return "EVENT_STOP"
	case uint32(unix.PTRACE_EVENT_FORK):
		return "FORK"
	case uint32(unix.PTRACE_EVENT_VFORK):
		return "VFORK"
	case uint32(unix.PTRACE_EVENT_CLONE):
		return "CLONE"
	case uint32(unix.PTRACE_EVENT_EXEC):
		return "EXEC"
	case uint32(unix.PTRACE_EVENT_EXIT):
		return "EXIT"
	case uint32(unix.PTRACE_EVENT_VFORK_DONE):
		return "VFORK_DONE"
	default:
		return fmt.Sprintf("ev=%d", ev)
	}
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

func decodeExitStatus(ws unix.WaitStatus) int {
	switch {
	case ws.Exited():
		return ws.ExitStatus()
	case ws.Signaled():
		return 128 + int(ws.Signal())
	default:
		return int(ws)
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
	hooksOnly    bool
	hasPreExec   bool
	hasPreExit   bool
}

func (p *ptraceContext) runPreExit() {
	if !p.hasPreExit {
		return
	}
	if err := p.executeHooks.RunHooks(attestation.StagePreExit, p.traceePid); err != nil {
		log.Errorf("PreExit hooks failed: %v", err)
	}
}

func enableTracing(c *exec.Cmd) {
	c.SysProcAttr = &unix.SysProcAttr{
		Ptrace: true,
	}
}

func (rc *CommandRun) trace(c *exec.Cmd, actx *attestation.AttestationContext, hasPreExec, hasPreExit bool) ([]ProcessInfo, error) {
	return rc.traceWithOptions(c, actx, false, hasPreExec, hasPreExit)
}

func (rc *CommandRun) runWithHooks(c *exec.Cmd, hasPreExec, hasPreExit bool) error {
	_, err := rc.traceWithOptions(c, nil, true, hasPreExec, hasPreExit)
	return err
}

func (rc *CommandRun) traceWithOptions(c *exec.Cmd, actx *attestation.AttestationContext, hooksOnly, hasPreExec, hasPreExit bool) ([]ProcessInfo, error) {
	pctx := &ptraceContext{
		traceePid:    c.Process.Pid,
		mainProgram:  c.Path,
		processes:    make(map[int]*ProcessInfo),
		executeHooks: rc.executeHooks,
		hooksOnly:    hooksOnly,
		hasPreExec:   hasPreExec,
		hasPreExit:   hasPreExit,
	}

	// Only set these when doing full tracing
	if actx != nil {
		pctx.hash = actx.Hashes()
		pctx.environmentCapturer = actx.EnvironmentCapturer()
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

const seizeOptions = unix.PTRACE_O_TRACESYSGOOD |
	unix.PTRACE_O_TRACEEXEC |
	unix.PTRACE_O_TRACEEXIT |
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
	if !p.hooksOnly {
		defer p.retryOpenedFiles()
	}

	defer p.runPreExit()

	status := unix.WaitStatus(0)
	_, err := unix.Wait4(p.traceePid, &status, 0, nil)
	if err != nil {
		return err
	}

	if p.hasPreExec {
		log.Infof("Running PreExec hooks")
		if err := p.executeHooks.RunHooks(attestation.StagePreExec, p.traceePid); err != nil {
			return fmt.Errorf("PreExec hooks failed: %w", err)
		}
	}

	if p.hooksOnly {
		log.Infof("Entering hooks-only mode")
		if p.hasPreExit {
			// Transition from the initial PTRACE_TRACEME attachment to PTRACE_SEIZE
			// so the network-trace gate can park a frozen task with PTRACE_LISTEN
			// and resume it on SIGCONT. This is only done in hooks-only mode: the
			// gate is a hooks-mode (network-trace) concern, and transitioning here
			// is safe because hooks-only mode does not rely on the initial
			// PTRACE_EVENT_EXEC (which already fired during the TRACEME phase).
			if err := p.transitionToSeize(); err != nil {
				return fmt.Errorf("transition to ptrace seize: %w", err)
			}
			log.Infof("Waiting for process exit to run PreExit hooks")
			return p.waitForExitOnly()
		}

		log.Infof("No PreExit hooks to run, detaching ptrace")
		if err := unix.PtraceDetach(p.traceePid); err != nil {
			return fmt.Errorf("failed to detach from process: %w", err)
		}
		_, err := unix.Wait4(p.traceePid, &status, 0, nil)
		if err != nil {
			return err
		}
		if status.Exited() {
			p.exitCode = status.ExitStatus()
		} else if status.Signaled() {
			p.exitCode = 128 + int(status.Signal())
		}
		return nil
	}

	// Full tracing mode
	if err := p.transitionToSeize(); err != nil {
		return fmt.Errorf("transition to ptrace seize: %w", err)
	}

	procInfo := p.getProcInfo(p.traceePid)
	procInfo.Program = p.mainProgram

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
					log.Debugf("(tracing) processing syscall: %w", err)
				}
			} else if isRegularTrap {
				// PTRACE_EVENT stops also come as regular SIGTRAP irrespective of TRACESYSGOOD
				// eventCode is in the high bits of the status

				if eventCode != 0 {
					// Case 2: Ptrace Event (Exit/Fork/Exec) -> Suppress signal
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

					case unix.PTRACE_EVENT_EXIT:
						if pid == p.traceePid {
							exitStatus, err := unix.PtraceGetEventMsg(pid)
							if err == nil {
								p.exitCode = decodeExitStatus(unix.WaitStatus(exitStatus))
							}
						}

						// Run the PreExit hook when the last tracked thread is
						// exiting, while it is still frozen here so cleanup
						// observes a paused process.
						if len(trackedTIDs) == 1 {
							if p.hasPreExit {
								log.Infof("Last thread pausing for exit. Running PreExit hooks.")
							}
							p.runPreExit()
						}

						delete(trackedTIDs, pid)

						// PTRACE_EVENT_EXIT requires PTRACE_CONT (not
						// PTRACE_SYSCALL) to finish exiting.
						if err := unix.PtraceCont(pid, 0); err != nil {
							if errors.Is(err, unix.ESRCH) {
								delete(trackedTIDs, pid)
							} else {
								log.Debugf("(tracing) ptrace cont exit error: %v", err)
							}
						}
						continue
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

	// See comment in waitForExitOnly()
	p.reapRemainingTasks()
	return nil
}

func (p *ptraceContext) waitForExitOnly() error {
	var status unix.WaitStatus

	log.Debugf("continuing process to wait for exit")

	trackedTIDs := map[int]struct{}{p.traceePid: {}}
	seizeHandoff := true
	gateInjected := make(map[int]bool)
	gateParked := make(map[int]bool)
	defer p.runPreExit()

	// INTERRUPT guarantees the tracee enters a PTRACE_EVENT_STOP regardless
	// of whether the DETACH(SIGSTOP) was consumed into a job-control sleep
	// before SEIZE attached. The seizeHandoff block consumes this stop.
	if err := ptraceInterrupt(p.traceePid); err != nil {
		log.Debugf("(tracing) ptrace interrupt after seize: %v", err)
	}

	for len(trackedTIDs) > 0 {
		pid, noChildren, err := waitAll(&status)
		if err != nil {
			return fmt.Errorf("wait4 failed: %w", err)
		}
		if noChildren {
			log.Debugf("(tracing) no children remaining, loop exit")
			break
		}

		if status.Exited() || status.Signaled() {
			log.Debugf("(tracing) exit pid=%d exited=%v signaled=%v code=%d TIDs=%d",
				pid, status.Exited(), status.Signaled(),
				func() int {
					if status.Exited() {
						return status.ExitStatus()
					}
					return -1
				}(),
				len(trackedTIDs))
			delete(trackedTIDs, pid)
			if pid == p.traceePid {
				if status.Exited() {
					p.exitCode = status.ExitStatus()
				} else if status.Signaled() {
					p.exitCode = 128 + int(status.Signal())
				}
			}
			continue // Wait for remaining threads
		}

		if status.Stopped() {
			sig := status.StopSignal()
			injectedSig := int(sig)
			eventCode := (uint32(status) >> 16) & 0xFFFF
			parked := false

			log.Debugf("(tracing) stop pid=%d %s ev=%s handoff=%v inj=%v park=%v TIDs=%d",
				pid, signalName(sig), ptraceEventName(eventCode),
				seizeHandoff, gateInjected[pid], gateParked[pid], len(trackedTIDs))

			// Post-SEIZE handoff: consume the initial PTRACE_EVENT_STOP
			// from the DETACH(SIGSTOP) signal injection or PTRACE_INTERRUPT.
			// WSTOPSIG is SIGSTOP (signal-injection) or SIGTRAP (INTERRUPT)
			if seizeHandoff && pid == p.traceePid &&
				eventCode == uint32(unix.PTRACE_EVENT_STOP) {
				seizeHandoff = false
				log.Debugf("(tracing) post-seize handoff pid=%d => PtraceCont(0)", pid)
				if err := unix.PtraceCont(pid, 0); err != nil {
					if errors.Is(err, unix.ESRCH) {
						delete(trackedTIDs, pid)
					} else {
						log.Debugf("(tracing) handoff PtraceCont failed: %v", err)
					}
				}
				continue
			}

			// SIGCONT wakes a task parked at a gate group-stop (via
			// PTRACE_LISTEN). Resume it normally.
			if sig == unix.SIGCONT && gateParked[pid] {
				delete(gateParked, pid)
				log.Debugf("(tracing) network-trace gate SIGCONT resume pid=%d", pid)
				if err := unix.PtraceCont(pid, 0); err != nil && !errors.Is(err, unix.ESRCH) {
					log.Debugf("(tracing) gate resume failed: %v", err)
				} else if errors.Is(err, unix.ESRCH) {
					delete(trackedTIDs, pid)
				}
				continue
			}

			//  Signal-delivery-stop, SIGSTOP with si_code == SI_KERNEL (our
			//  bpf_send_signal gate): INJECT it so the task enters a real
			//  group-stop.
			if sig == unix.SIGSTOP && eventCode == 0 && isGateSIGSTOP(pid) {
				log.Debugf("(tracing) network-trace gate SIGSTOP inject pid=%d", pid)
				gateInjected[pid] = true
				trackedTIDs[pid] = struct{}{}
				if err := unix.PtraceCont(pid, int(unix.SIGSTOP)); err != nil {
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
				// Group-stop that follows our gate inject: park it with LISTEN so
				// it stays frozen while the kernel still reports the SIGCONT wake.
				delete(gateInjected, pid)
				if err := ptraceListen(pid); err == nil {
					log.Debugf("(tracing) network-trace gate PARK (LISTEN) pid=%d", pid)
					gateParked[pid] = true
					trackedTIDs[pid] = struct{}{}
					parked = true
				} else {
					log.Debugf("(tracing) gate LISTEN failed pid=%d: %v", pid, err)
				}
				if parked {
					continue
				}
			}

			// We supress all other stopping signals for keep the tracer logic simpler.
			// In practice this should be fine. Acceptable tradeoff. Improvement may be
			// using get_signal_info to try to distinguish signals which we want to pass
			// versus regular user issued SIGSTOPs we should respect.
			if isStoppingSignal(sig) {
				injectedSig = 0
				trackedTIDs[pid] = struct{}{}
			}

			if sig == unix.SIGTRAP {
				if eventCode != 0 {
					injectedSig = 0 // Swallow signal

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
					case unix.PTRACE_EVENT_EXIT:
						if pid == p.traceePid {
							exitStatus, err := unix.PtraceGetEventMsg(pid)
							if err == nil {
								p.exitCode = decodeExitStatus(unix.WaitStatus(exitStatus))
							}
						}

						if len(trackedTIDs) == 1 {
							if p.hasPreExit {
								log.Infof("Last thread pausing for exit. Running PreExit hooks.")
							}
							p.runPreExit()
						}

						delete(trackedTIDs, pid)
					}
				}
			}

			if err := unix.PtraceCont(pid, injectedSig); err != nil {
				if errors.Is(err, unix.ESRCH) {
					delete(trackedTIDs, pid)
				} else {
					log.Debugf("(tracing) failed to continue with signal %d: %v", injectedSig, err)
				}
			}
		}
	}

	// The loop exits when trackedTIDs is drained, always at
	// PTRACE_EVENT_EXIT but the PtraceCont that follows sends the
	// tracee to its final WIFEXITED, which arrives after the loop has
	// stopped checking Wait4. Reap any remaining exit notifications to
	// prevent the tracee from lingering as a zombie (Z or Z+). It needs
	// to be a loop as which signal gets delivered to tracer depends on the kernel
	// (for multiple threads) PTRACE_EVENT_EXIT or WIFEXITED.
	p.reapRemainingTasks()

	return nil
}

func (p *ptraceContext) reapRemainingTasks() {
	for {
		var status unix.WaitStatus
		w, err := unix.Wait4(-1, &status, unix.WALL, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.ECHILD) {
			break
		}
		// no need to set exit code, set at previous exits or PTRACE_EVENT_EXIT
		if w > 0 {
			log.Debugf("(tracing) final reap pid=%d exited=%v signaled=%v code=%d",
				w, status.Exited(), status.Signaled(),
				func() int {
					if status.Exited() {
						return status.ExitStatus()
					}
					return -1
				}())
		}
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
