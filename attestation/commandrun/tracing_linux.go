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
	MAX_PATH_LEN = 4096
)

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

func (p *ptraceContext) runTrace() error {
	if !p.hooksOnly {
		defer p.retryOpenedFiles()
	}

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
			log.Infof("Waiting for process exit to run PreExit hooks")
			// Change the signal handling in waitForExitOnly if ptrace options are changed from PTRACE_O_TRACEEXIT
			if err := unix.PtraceSetOptions(p.traceePid, unix.PTRACE_O_TRACEEXIT); err != nil {
				return err
			}
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
	if err := unix.PtraceSetOptions(p.traceePid, unix.PTRACE_O_TRACESYSGOOD|unix.PTRACE_O_TRACEEXEC|unix.PTRACE_O_TRACEEXIT|unix.PTRACE_O_TRACEVFORK|unix.PTRACE_O_TRACEFORK|unix.PTRACE_O_TRACECLONE); err != nil {
		return err
	}

	procInfo := p.getProcInfo(p.traceePid)
	procInfo.Program = p.mainProgram
	if err := unix.PtraceSyscall(p.traceePid, 0); err != nil {
		return err
	}

	for {
		pid, err := unix.Wait4(-1, &status, unix.WALL, nil)
		if err != nil {
			return err
		}
		if pid == p.traceePid && status.Exited() {
			p.exitCode = status.ExitStatus()
			return nil
		}
		if pid == p.traceePid && status.Signaled() {
			p.exitCode = 128 + int(status.Signal())
			return nil
		}

		if status.Stopped() {
			sig := status.StopSignal()

			// Distinguish the 3 types of traps
			// since we set PTRACE_O_TRACESYSGOOD any traps triggered by ptrace will have its signal set to SIGTRAP|0x80.
			// If we catch a signal that isn't a ptrace'd signal we want to let the process continue to handle that signal, so we inject the thrown signal back to the process.
			// If it was a ptrace SIGTRAP we suppress the signal and send 0
			isSyscallTrap := sig == (unix.SIGTRAP | 0x80)
			isRegularTrap := sig == unix.SIGTRAP

			// Inject the signal back (e.g., SIGINT, SIGTERM, or Real SIGTRAP)
			injectedSig := int(sig)

			if isSyscallTrap {
				injectedSig = 0
				if err := p.nextSyscall(pid); err != nil {
					log.Debugf("(tracing) processing syscall: %w", err)
				}
			} else if isRegularTrap {
				// PTRACE_EVENT stops also come as regular SIGTRAP irrespective of TRACESYSGOOD
				// eventCode is in the high bits of the status
				eventCode := (uint32(status) >> 16) & 0xFFFF

				if eventCode != 0 {
					// Case 2: Ptrace Event (Exit/Fork/Exec) -> Suppress signal
					injectedSig = 0

					if eventCode == unix.PTRACE_EVENT_EXIT && pid == p.traceePid && p.hasPreExit {
						if err := p.executeHooks.RunHooks(attestation.StagePreExit, pid); err != nil {
							log.Errorf("PreExit hooks failed: %v", err)
						}
					}
				}
			}

			if err := unix.PtraceSyscall(pid, injectedSig); err != nil {
				log.Debugf("(tracing) ptrace syscall error: %w", err)
			}
		} else {
			if err := unix.PtraceSyscall(pid, 0); err != nil {
				log.Debugf("(tracing) got error from ptrace syscall: %w", err)
			}
		}
	}
}

func (p *ptraceContext) waitForExitOnly() error {
	var status unix.WaitStatus

	log.Debugf("continuing process to wait for exit")
	if err := unix.PtraceCont(p.traceePid, 0); err != nil {
		return fmt.Errorf("failed to continue: %w", err)
	}

	for {
		_, err := unix.Wait4(p.traceePid, &status, 0, nil)
		if err != nil {
			return fmt.Errorf("wait4 failed: %w", err)
		}

		if status.Exited() {
			p.exitCode = status.ExitStatus()
			return nil
		}
		if status.Signaled() {
			p.exitCode = 128 + int(status.Signal())
			return nil
		}

		if status.Stopped() {
			sig := status.StopSignal()

			injectedSig := int(sig)

			if sig == unix.SIGTRAP {
				eventCode := (uint32(status) >> 16) & 0xFFFF

				if eventCode != 0 {
					// Ptrace Event (EXIT) -> Swallow signal
					injectedSig = 0

					// As we setup with only PTRACE_O_TRACEEXIT, only this event would be emitted
					// Still, eventCode != 0 and eventCode == unix.PTRACE_EVENT_EXIT are separated for defensive
					// programming
					if eventCode == unix.PTRACE_EVENT_EXIT {
						log.Infof("caught exit event for pid %d", p.traceePid)
						if err := p.executeHooks.RunHooks(attestation.StagePreExit, p.traceePid); err != nil {
							log.Errorf("PreExit hooks failed: %v", err)
						}

						exitStatus, err := unix.PtraceGetEventMsg(p.traceePid)
						if err == nil {
							p.exitCode = int(exitStatus >> 8)
						}

						// Cont is required after PTRACE_EVENT_EXIT event stop, tracee is alive, needs to be cont
						err = unix.PtraceCont(p.traceePid, 0)
						if err != nil {
							log.Errorf("Final PtraceCont failed (process likely already dead): %v", err)
						}
						// clear the zombie process using a wait signal
						wPid, err := unix.Wait4(p.traceePid, &status, 0, nil)
						if err != nil {
							// ECHILD - child process has likely already been cleared
							if !errors.Is(err, unix.ECHILD) {
								log.Errorf("wPid: %d, wait4 failed: %v", wPid, err)
							}
						}
						return nil
					}
				}
				// If eventCode == 0, it is a REAL trap (int3).
				// injectedSig remains SIGTRAP (5).
			}

			if err := unix.PtraceCont(p.traceePid, injectedSig); err != nil {
				return fmt.Errorf("failed to continue with signal %d: %w", injectedSig, err)
			}
		}
	}
}

func (p *ptraceContext) retryOpenedFiles() {
	// after tracing, look through opened files to try to resolve any newly created files
	procInfo := p.getProcInfo(p.traceePid)

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

		program, err := p.readSyscallReg(pid, argArray[0], MAX_PATH_LEN)
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
		file, err := p.readSyscallReg(pid, argArray[1], MAX_PATH_LEN)
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
		Len:  getNativeUint(n),
	}

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
