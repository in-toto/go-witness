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
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/environment"
	"github.com/in-toto/go-witness/log"
	"golang.org/x/sys/unix"
)

// linuxTracer implements the Tracer interface using ptrace on Linux
type linuxTracer struct {
	cmd                 *exec.Cmd
	ctx                 *attestation.AttestationContext
	opts                TracerOptions
	parentPid           int
	mainProgram         string
	processes           map[int]*ProcessInfo
	processLock         sync.RWMutex
	exitCode            int
	hash                []cryptoutil.DigestValue
	environmentCapturer *environment.Capture
	startTime           *time.Time
	endTime             *time.Time
	
	// Track syscall state for capturing return values
	syscallEntry        map[int]syscallState // pid -> syscall state
}

// syscallState tracks a syscall between entry and exit
type syscallState struct {
	syscallID uint64
	args      [6]uintptr // syscall arguments
}

// Buffer pool to reduce allocations
var bufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 4096)
		return &buf
	},
}

func newPlatformTracer(ctx *attestation.AttestationContext, opts TracerOptions) Tracer {
	lt := &linuxTracer{
		ctx:          ctx,
		opts:         opts,
		processes:    make(map[int]*ProcessInfo),
		syscallEntry: make(map[int]syscallState),
	}
	
	// Handle nil context gracefully
	if ctx != nil {
		lt.hash = ctx.Hashes()
		lt.environmentCapturer = ctx.EnvironmentCapturer()
	}
	
	return lt
}

func (t *linuxTracer) Start(cmd *exec.Cmd) error {
	t.cmd = cmd
	t.mainProgram = cmd.Path
	
	// Record start time
	now := time.Now()
	t.startTime = &now
	
	// Enable ptrace
	cmd.SysProcAttr = &unix.SysProcAttr{
		Ptrace: true,
	}
	
	if err := cmd.Start(); err != nil {
		return err
	}
	
	t.parentPid = cmd.Process.Pid
	return nil
}

func (t *linuxTracer) Wait() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	
	// Record end time when we're done
	defer func() {
		now := time.Now()
		t.endTime = &now
	}()
	
	// Wait for the initial stop
	status := unix.WaitStatus(0)
	_, err := unix.Wait4(t.parentPid, &status, 0, nil)
	if err != nil {
		return &TracerError{Op: "wait4", PID: PID(t.parentPid), Err: err}
	}

	// Set ptrace options
	ptraceOpts := unix.PTRACE_O_TRACESYSGOOD | unix.PTRACE_O_TRACEEXEC | 
		unix.PTRACE_O_TRACEEXIT | unix.PTRACE_O_TRACEVFORK | 
		unix.PTRACE_O_TRACEFORK | unix.PTRACE_O_TRACECLONE
	
	if err := unix.PtraceSetOptions(t.parentPid, ptraceOpts); err != nil {
		return &TracerError{Op: "ptrace set options", PID: PID(t.parentPid), Err: err}
	}

	// Initialize the main process info
	procInfo := t.getOrCreateProcess(t.parentPid)
	procInfo.Program = t.mainProgram
	log.Debugf("Initialized main process: PID=%d Program=%s", t.parentPid, t.mainProgram)
	
	// Continue execution
	if err := unix.PtraceSyscall(t.parentPid, 0); err != nil {
		return &TracerError{Op: "ptrace syscall", PID: PID(t.parentPid), Err: err}
	}

	// Main tracing loop
	for {
		pid, err := unix.Wait4(-1, &status, unix.WALL, nil)
		if err != nil {
			return &TracerError{Op: "wait4 in loop", PID: PID(pid), Err: err}
		}

		if status.Exited() {
			exitCode := status.ExitStatus()
			log.Debugf("process %d exited with code %d", pid, exitCode)
			if pid == t.parentPid {
				t.exitCode = exitCode
				break
			}
			continue
		}

		if status.Signaled() {
			log.Debugf("process %d signaled with %s", pid, status.Signal())
			continue
		}

		// Handle system call tracing
		if err := t.handleSyscall(pid, status); err != nil {
			log.Debugf("error handling syscall for pid %d: %v", pid, err)
		}

		// Continue the process
		if err := unix.PtraceSyscall(pid, 0); err != nil {
			log.Debugf("ptrace syscall error: %v", err)
			if err == unix.ESRCH {
				continue
			}
		}
	}

	// Post-process to retry file operations that may have failed
	if t.opts.EnableHashing {
		t.retryOpenedFiles()
	}
	
	// Always update process info at the end to ensure we have complete data
	t.updateAllProcessInfo()

	if t.exitCode != 0 {
		return fmt.Errorf("exit status %v", t.exitCode)
	}
	
	return nil
}

func (t *linuxTracer) GetProcessTree() []ProcessInfo {
	t.processLock.RLock()
	defer t.processLock.RUnlock()
	
	processes := make([]ProcessInfo, 0, len(t.processes))
	for _, procInfo := range t.processes {
		processes = append(processes, *procInfo)
	}
	return processes
}

func (t *linuxTracer) GetStartTime() *time.Time {
	return t.startTime
}

func (t *linuxTracer) GetEndTime() *time.Time {
	return t.endTime
}

func (t *linuxTracer) handleSyscall(pid int, status unix.WaitStatus) error {
	// Check if this is a syscall-stop event
	if status.StopSignal() == unix.SIGTRAP|0x80 {
		regs := getRegisters()
		if err := unix.PtraceGetRegs(pid, regs); err != nil {
			return &TracerError{Op: "get regs", PID: PID(pid), Err: err}
		}

		// Check if this is entry or exit
		if state, exists := t.syscallEntry[pid]; exists {
			// This is syscall exit - handle return value
			returnValue := getSyscallReturn(regs)
			t.handleSyscallExit(pid, state, returnValue)
			delete(t.syscallEntry, pid)
			return nil
		}

		// This is syscall entry
		syscallID := getSyscallID(regs)
		
		// Store syscall state for capturing return value
		t.syscallEntry[pid] = syscallState{
			syscallID: syscallID,
			args: [6]uintptr{
				getArg0(regs), getArg1(regs), getArg2(regs),
				getArg3(regs), getArg4(regs), getArg5(regs),
			},
		}
		
		switch syscallID {
		case unix.SYS_EXECVE:
			t.handleExecve(pid, regs)
		case unix.SYS_OPENAT:
			// Always handle openat to track file writes
			t.handleOpenat(pid, regs)
		// File write syscalls
		case unix.SYS_WRITE, unix.SYS_WRITEV, unix.SYS_PWRITE64:
			t.handleWrite(pid, regs)
		// Network syscalls when EnableNetworkTrace is true
		case unix.SYS_SOCKET:
			if t.opts.EnableNetworkTrace {
				t.handleSocket(pid, regs)
			}
		case unix.SYS_CONNECT:
			if t.opts.EnableNetworkTrace {
				t.handleConnect(pid, regs)
			}
		case unix.SYS_BIND:
			if t.opts.EnableNetworkTrace {
				t.handleBind(pid, regs)
			}
		case unix.SYS_LISTEN:
			if t.opts.EnableNetworkTrace {
				t.handleListen(pid, regs)
			}
		case unix.SYS_ACCEPT, unix.SYS_ACCEPT4:
			if t.opts.EnableNetworkTrace {
				t.handleAccept(pid, regs)
			}
		// Don't handle send/recv on entry - wait for exit to get byte count
		}
	}
	
	return nil
}

func (t *linuxTracer) handleExecve(pid int, regs *syscallRegisters) {
	programReg := getArg0(regs)
	program, err := t.readSyscallString(pid, programReg, 4096)
	if err != nil {
		log.Debugf("error reading program path: %v", err)
		return
	}

	procInfo := t.getOrCreateProcess(pid)
	procInfo.Program = program
	log.Debugf("EXECVE: PID=%d executing %s", pid, program)
}

func (t *linuxTracer) handleOpenat(pid int, regs *syscallRegisters) {
	fileReg := getArg1(regs)
	flagsReg := getArg2(regs)
	
	file, err := t.readSyscallString(pid, fileReg, 4096)
	if err != nil {
		return
	}

	// Check if file is being opened for writing
	flags := int(flagsReg)
	isWrite := flags&unix.O_WRONLY != 0 || flags&unix.O_RDWR != 0
	isCreate := flags&unix.O_CREAT != 0

	// Skip special files
	if IsSpecialPath(file) {
		return
	}

	procInfo := t.getOrCreateProcess(pid)
	
	if isWrite || isCreate {
		// Track as a written file
		if procInfo.WrittenFiles == nil {
			procInfo.WrittenFiles = make(map[string]cryptoutil.DigestSet)
		}
		procInfo.WrittenFiles[file] = cryptoutil.DigestSet{}
		log.Debugf("OPENAT: PID=%d opened %s for writing", pid, file)
	} else {
		// Track as a read file
		if procInfo.OpenedFiles == nil {
			procInfo.OpenedFiles = make(map[string]cryptoutil.DigestSet)
		}
		
		// Calculate digest if hashing is enabled and we have hashes
		if t.opts.EnableHashing && t.hash != nil {
			if digest, err := cryptoutil.CalculateDigestSetFromFile(file, t.hash); err == nil {
				procInfo.OpenedFiles[file] = digest
			} else {
				// Store empty digest to retry later
				procInfo.OpenedFiles[file] = cryptoutil.DigestSet{}
			}
		} else {
			// Just track that the file was opened
			procInfo.OpenedFiles[file] = cryptoutil.DigestSet{}
		}
	}
}

func (t *linuxTracer) handleSocket(pid int, regs *syscallRegisters) {
	domain := int(getArg0(regs))
	sockType := int(getArg1(regs))
	protocol := int(getArg2(regs))
	
	procInfo := t.getOrCreateProcess(pid)
	if procInfo.NetworkActivity == nil {
		procInfo.NetworkActivity = &NetworkActivity{}
	}
	
	now := time.Now()
	socketInfo := SocketInfo{
		Domain:   domainToString(domain),
		Type:     socketTypeToString(sockType),
		Protocol: protocolToString(protocol),
		Created:  &now,
	}
	
	procInfo.NetworkActivity.Sockets = append(procInfo.NetworkActivity.Sockets, socketInfo)
	log.Debugf("SOCKET: PID=%d domain=%s type=%s protocol=%s", pid, socketInfo.Domain, socketInfo.Type, socketInfo.Protocol)
}

func (t *linuxTracer) handleConnect(pid int, regs *syscallRegisters) {
	addrPtr := getArg1(regs)
	addrLen := int(getArg2(regs))
	
	procInfo := t.getOrCreateProcess(pid)
	if procInfo.NetworkActivity == nil {
		procInfo.NetworkActivity = &NetworkActivity{}
	}
	
	now := time.Now()
	connInfo := ConnectionInfo{
		Type:      "connect",
		Timestamp: &now,
		Success:   true, // Will be updated on syscall exit
	}
	
	// Try to read the socket address
	if addr, err := t.readSockaddr(pid, addrPtr, addrLen); err == nil {
		connInfo.RemoteAddr = addr
	}
	
	procInfo.NetworkActivity.Connections = append(procInfo.NetworkActivity.Connections, connInfo)
	log.Debugf("CONNECT: PID=%d to %s", pid, connInfo.RemoteAddr)
}

func (t *linuxTracer) handleBind(pid int, regs *syscallRegisters) {
	addrPtr := getArg1(regs)
	addrLen := int(getArg2(regs))
	
	procInfo := t.getOrCreateProcess(pid)
	if procInfo.NetworkActivity == nil {
		procInfo.NetworkActivity = &NetworkActivity{}
	}
	
	now := time.Now()
	connInfo := ConnectionInfo{
		Type:      "bind",
		Timestamp: &now,
		Success:   true,
	}
	
	// Try to read the socket address
	if addr, err := t.readSockaddr(pid, addrPtr, addrLen); err == nil {
		connInfo.LocalAddr = addr
	}
	
	procInfo.NetworkActivity.Connections = append(procInfo.NetworkActivity.Connections, connInfo)
	log.Debugf("BIND: PID=%d to %s", pid, connInfo.LocalAddr)
}

func (t *linuxTracer) handleListen(pid int, regs *syscallRegisters) {
	procInfo := t.getOrCreateProcess(pid)
	if procInfo.NetworkActivity == nil {
		procInfo.NetworkActivity = &NetworkActivity{}
	}
	
	now := time.Now()
	connInfo := ConnectionInfo{
		Type:      "listen",
		Timestamp: &now,
		Success:   true,
	}
	
	procInfo.NetworkActivity.Connections = append(procInfo.NetworkActivity.Connections, connInfo)
	log.Debugf("LISTEN: PID=%d", pid)
}

func (t *linuxTracer) handleAccept(pid int, regs *syscallRegisters) {
	procInfo := t.getOrCreateProcess(pid)
	if procInfo.NetworkActivity == nil {
		procInfo.NetworkActivity = &NetworkActivity{}
	}
	
	now := time.Now()
	connInfo := ConnectionInfo{
		Type:      "accept",
		Timestamp: &now,
		Success:   true,
	}
	
	procInfo.NetworkActivity.Connections = append(procInfo.NetworkActivity.Connections, connInfo)
	log.Debugf("ACCEPT: PID=%d", pid)
}

// handleSyscallExit processes syscall return values
func (t *linuxTracer) handleSyscallExit(pid int, state syscallState, returnValue int64) {
	switch state.syscallID {
	case unix.SYS_SENDTO, unix.SYS_SENDMSG, unix.SYS_SENDMMSG, unix.SYS_WRITE, unix.SYS_WRITEV, unix.SYS_PWRITE64:
		if returnValue > 0 {
			procInfo := t.getOrCreateProcess(pid)
			if t.opts.EnableNetworkTrace && procInfo.NetworkActivity != nil {
				// For network sends
				if state.syscallID != unix.SYS_WRITE && state.syscallID != unix.SYS_WRITEV && state.syscallID != unix.SYS_PWRITE64 {
					procInfo.NetworkActivity.BytesSent += uint64(returnValue)
					log.Debugf("SEND: PID=%d sent %d bytes", pid, returnValue)
				}
			}
		}
	case unix.SYS_RECVFROM, unix.SYS_RECVMSG, unix.SYS_RECVMMSG, unix.SYS_READ, unix.SYS_READV, unix.SYS_PREAD64:
		if returnValue > 0 {
			procInfo := t.getOrCreateProcess(pid)
			if t.opts.EnableNetworkTrace && procInfo.NetworkActivity != nil {
				// For network receives
				if state.syscallID != unix.SYS_READ && state.syscallID != unix.SYS_READV && state.syscallID != unix.SYS_PREAD64 {
					procInfo.NetworkActivity.BytesReceived += uint64(returnValue)
					log.Debugf("RECV: PID=%d received %d bytes", pid, returnValue)
				}
			}
		}
	case unix.SYS_CONNECT, unix.SYS_BIND:
		// Update connection success/failure based on return value
		if returnValue < 0 && t.opts.EnableNetworkTrace {
			procInfo := t.getOrCreateProcess(pid)
			if procInfo.NetworkActivity != nil && len(procInfo.NetworkActivity.Connections) > 0 {
				// Mark the last connection as failed
				lastIdx := len(procInfo.NetworkActivity.Connections) - 1
				procInfo.NetworkActivity.Connections[lastIdx].Success = false
				procInfo.NetworkActivity.Connections[lastIdx].ErrorMessage = fmt.Sprintf("errno %d", -returnValue)
			}
		}
	}
}

// handleWrite tracks file write operations
func (t *linuxTracer) handleWrite(pid int, regs *syscallRegisters) {
	fd := int(getArg0(regs))
	
	// Skip standard streams
	if fd <= 2 {
		log.Debugf("WRITE: PID=%d skipping std stream fd=%d", pid, fd)
		return
	}
	
	procInfo := t.getOrCreateProcess(pid)
	
	// Try to resolve the file path from the fd
	fdPath := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
	if target, err := os.Readlink(fdPath); err == nil {
		// Skip special files
		if IsSpecialPath(target) {
			log.Debugf("WRITE: PID=%d skipping special file %s", pid, target)
			return
		}
		
		// Initialize WrittenFiles if needed
		if procInfo.WrittenFiles == nil {
			procInfo.WrittenFiles = make(map[string]cryptoutil.DigestSet)
		}
		
		// Mark file as written (digest will be calculated later if hashing enabled)
		procInfo.WrittenFiles[target] = cryptoutil.DigestSet{}
		log.Debugf("WRITE: PID=%d to file %s (fd=%d)", pid, target, fd)
	} else {
		log.Debugf("WRITE: PID=%d failed to resolve fd=%d: %v", pid, fd, err)
	}
}

func (t *linuxTracer) getOrCreateProcess(pid int) *ProcessInfo {
	t.processLock.Lock()
	defer t.processLock.Unlock()
	
	if procInfo, ok := t.processes[pid]; ok {
		return procInfo
	}

	procInfo := &ProcessInfo{
		ProcessID:   pid,
		OpenedFiles: make(map[string]cryptoutil.DigestSet),
	}

	// Read process information from /proc
	t.updateProcessInfo(procInfo)
	t.processes[pid] = procInfo
	
	return procInfo
}

func (t *linuxTracer) updateProcessInfo(procInfo *ProcessInfo) {
	pid := procInfo.ProcessID
	
	// Read various /proc files
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	statusData, err := os.ReadFile(statusPath)
	if err == nil {
		// Deprecated field - no longer collected
		if ppid, err := getPPIDFromStatus(statusData); err == nil {
			procInfo.ParentPID = ppid
		}
		// Extract memory info from status
		if rss := getVmRSSFromStatus(statusData); rss > 0 {
			procInfo.MemoryRSS = rss
		}
		if peak := getVmPeakFromStatus(statusData); peak > 0 {
			procInfo.PeakMemoryRSS = peak
		}
	}
	
	// Read CPU usage from /proc/[pid]/stat
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	if statData, err := os.ReadFile(statPath); err == nil {
		if userTime, sysTime, err := getCPUTimeFromStat(statData); err == nil {
			procInfo.CPUTimeUser = &userTime
			procInfo.CPUTimeSystem = &sysTime
		}
	}

	// Deprecated field Comm - no longer collected

	// Read cmdline
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	if cmdline, err := os.ReadFile(cmdlinePath); err == nil {
		procInfo.Cmdline = cleanString(string(cmdline))
	}

	// Deprecated field Environ - no longer collected for security reasons

	// Calculate program digests if hashing is enabled and we have hashes
	if t.opts.EnableHashing && t.hash != nil {
		// Exe digest
		exePath := fmt.Sprintf("/proc/%d/exe", pid)
		if exeDigest, err := cryptoutil.CalculateDigestSetFromFile(exePath, t.hash); err == nil {
			procInfo.ExeDigest = exeDigest
			log.Debugf("Calculated exe digest for PID %d", pid)
		} else {
			log.Debugf("Failed to calculate exe digest for PID %d: %v", pid, err)
		}

		// Program digest (if different from exe)
		if procInfo.Program != "" {
			if programDigest, err := cryptoutil.CalculateDigestSetFromFile(procInfo.Program, t.hash); err == nil {
				procInfo.ProgramDigest = programDigest
				log.Debugf("Calculated program digest for PID %d: %s", pid, procInfo.Program)
			} else {
				log.Debugf("Failed to calculate program digest for PID %d: %v", pid, err)
			}
		}
	}
}

func (t *linuxTracer) retryOpenedFiles() {
	if !t.opts.EnableHashing || t.hash == nil {
		return
	}

	t.processLock.Lock()
	defer t.processLock.Unlock()

	for _, procInfo := range t.processes {
		for file, digest := range procInfo.OpenedFiles {
			if len(digest) == 0 {
				// Retry calculating digest
				if newDigest, err := cryptoutil.CalculateDigestSetFromFile(file, t.hash); err == nil {
					procInfo.OpenedFiles[file] = newDigest
				}
			}
		}
	}
}

func (t *linuxTracer) updateAllProcessInfo() {
	t.processLock.Lock()
	defer t.processLock.Unlock()
	
	// Re-update all process info at the end to ensure we have complete data
	for pid, procInfo := range t.processes {
		// Skip if process has already exited
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); os.IsNotExist(err) {
			log.Debugf("Process %d has already exited, skipping update", pid)
			continue
		}
		t.updateProcessInfo(procInfo)
	}
}

func (t *linuxTracer) readSyscallString(pid int, addr uintptr, maxLen int) (string, error) {
	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)
	
	buf := *bufPtr
	if maxLen > len(buf) {
		buf = make([]byte, maxLen)
	}
	
	localIov := unix.Iovec{
		Base: &buf[0],
		Len:  getNativeUint(maxLen),
	}
	
	remoteIov := unix.RemoteIovec{
		Base: addr,
		Len:  maxLen,
	}
	
	n, err := unix.ProcessVMReadv(pid, []unix.Iovec{localIov}, []unix.RemoteIovec{remoteIov}, 0)
	if err != nil || n == 0 {
		return "", err
	}
	
	// Find null terminator
	size := bytes.IndexByte(buf[:n], 0)
	if size == -1 {
		size = int(n)
	}
	
	return string(buf[:size]), nil
}

// Network syscall helpers

func (t *linuxTracer) readSockaddr(pid int, addr uintptr, addrLen int) (string, error) {
	if addrLen < 2 || addrLen > 128 {
		return "", fmt.Errorf("invalid address length: %d", addrLen)
	}
	
	data := make([]byte, addrLen)
	localIov := unix.Iovec{
		Base: &data[0],
		Len:  getNativeUint(addrLen),
	}
	
	remoteIov := unix.RemoteIovec{
		Base: addr,
		Len:  addrLen,
	}
	
	n, err := unix.ProcessVMReadv(pid, []unix.Iovec{localIov}, []unix.RemoteIovec{remoteIov}, 0)
	if err != nil || n == 0 {
		return "", err
	}
	
	// Parse based on address family
	if len(data) >= 2 {
		family := uint16(data[0]) | uint16(data[1])<<8
		switch family {
		case unix.AF_INET:
			if len(data) >= 8 {
				// IPv4 address
				port := uint16(data[2])<<8 | uint16(data[3])
				ip := fmt.Sprintf("%d.%d.%d.%d", data[4], data[5], data[6], data[7])
				return fmt.Sprintf("%s:%d", ip, port), nil
			}
		case unix.AF_INET6:
			if len(data) >= 28 {
				// IPv6 address - simplified format
				port := uint16(data[2])<<8 | uint16(data[3])
				return fmt.Sprintf("[IPv6]:%d", port), nil
			}
		case unix.AF_UNIX:
			// Unix domain socket
			if len(data) > 2 {
				path := string(data[2:])
				if idx := bytes.IndexByte([]byte(path), 0); idx >= 0 {
					path = path[:idx]
				}
				return fmt.Sprintf("unix:%s", path), nil
			}
		}
	}
	
	return fmt.Sprintf("unknown_family_%d", data[0]), nil
}

func domainToString(domain int) string {
	switch domain {
	case unix.AF_INET:
		return "AF_INET"
	case unix.AF_INET6:
		return "AF_INET6"
	case unix.AF_UNIX:
		return "AF_UNIX"
	case unix.AF_NETLINK:
		return "AF_NETLINK"
	default:
		return fmt.Sprintf("AF_%d", domain)
	}
}

func socketTypeToString(sockType int) string {
	// Mask out flags like SOCK_CLOEXEC and SOCK_NONBLOCK
	baseType := sockType & 0xf
	switch baseType {
	case unix.SOCK_STREAM:
		return "SOCK_STREAM"
	case unix.SOCK_DGRAM:
		return "SOCK_DGRAM"
	case unix.SOCK_RAW:
		return "SOCK_RAW"
	case unix.SOCK_SEQPACKET:
		return "SOCK_SEQPACKET"
	default:
		return fmt.Sprintf("SOCK_%d", baseType)
	}
}

func protocolToString(protocol int) string {
	switch protocol {
	case 0:
		return "default"
	case unix.IPPROTO_TCP:
		return "tcp"
	case unix.IPPROTO_UDP:
		return "udp"
	case unix.IPPROTO_ICMP:
		return "icmp"
	case unix.IPPROTO_ICMPV6:
		return "icmpv6"
	default:
		return fmt.Sprintf("proto_%d", protocol)
	}
}

// Helper functions for resource usage tracking

func getVmRSSFromStatus(status []byte) uint64 {
	statusStr := string(status)
	lines := strings.Split(statusStr, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if val, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					// Convert from KB to bytes
					return val * 1024
				}
			}
		}
	}
	return 0
}

func getVmPeakFromStatus(status []byte) uint64 {
	statusStr := string(status)
	lines := strings.Split(statusStr, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "VmPeak:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if val, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					// Convert from KB to bytes
					return val * 1024
				}
			}
		}
	}
	return 0
}

func getCPUTimeFromStat(stat []byte) (time.Duration, time.Duration, error) {
	// The /proc/[pid]/stat format has many fields. CPU times are:
	// Field 14: utime (user mode jiffies)
	// Field 15: stime (kernel mode jiffies)
	statStr := string(stat)
	
	// Find the last ')' to skip the command which might contain spaces/parens
	lastParen := strings.LastIndex(statStr, ")")
	if lastParen == -1 {
		return 0, 0, fmt.Errorf("invalid stat format")
	}
	
	// Fields after the command
	fields := strings.Fields(statStr[lastParen+1:])
	if len(fields) < 13 {
		return 0, 0, fmt.Errorf("insufficient fields in stat")
	}
	
	// Fields are 0-indexed after the command, so utime is at index 11, stime at 12
	utime, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	
	stime, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	
	// Convert jiffies to duration (typically 100 Hz, so 1 jiffy = 10ms)
	// Use sysconf to get the actual clock tick rate
	clockTicks := uint64(100) // Default, should use sysconf(_SC_CLK_TCK)
	
	// Check for overflow before converting to int64
	const maxDuration = uint64(^time.Duration(0) >> 1)
	if utime > maxDuration/uint64(time.Second)*clockTicks {
		utime = maxDuration / uint64(time.Second) * clockTicks
	}
	if stime > maxDuration/uint64(time.Second)*clockTicks {
		stime = maxDuration / uint64(time.Second) * clockTicks
	}
	
	userTime := time.Duration(utime) * time.Second / time.Duration(clockTicks)
	sysTime := time.Duration(stime) * time.Second / time.Duration(clockTicks)
	
	return userTime, sysTime, nil
}

// Additional helper functions from existing implementation

func cleanString(s string) string {
	s = strings.ReplaceAll(s, "\x00", " ")
	s = strings.TrimSpace(s)
	return s
}

func getPPIDFromStatus(status []byte) (int, error) {
	statusStr := string(status)
	lines := strings.Split(statusStr, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return strconv.Atoi(fields[1])
			}
		}
	}
	return 0, fmt.Errorf("PPid not found")
}

