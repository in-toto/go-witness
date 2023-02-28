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
	"crypto"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/testifysec/go-witness/attestation"
	"github.com/testifysec/go-witness/attestation/environment"
	"github.com/testifysec/go-witness/cryptoutil"
	"github.com/testifysec/go-witness/log"
	"golang.org/x/sys/unix"
)

const (
	MAX_PATH_LEN = 4096
)

type ptraceContext struct {
	parentPid            int
	mainProgram          string
	processes            map[int]*ProcessInfo
	exitCode             int
	hash                 []crypto.Hash
	environmentBlockList map[string]struct{}
}

func (r *CommandRun) trace(c *exec.Cmd, actx *attestation.AttestationContext) ([]ProcessInfo, error) {
	pctx := &ptraceContext{
		parentPid:            c.Process.Pid,
		mainProgram:          c.Path,
		processes:            make(map[int]*ProcessInfo),
		hash:                 actx.Hashes(),
		environmentBlockList: r.environmentBlockList,
	}

	if err := pctx.runTrace(); err != nil {
		log.Debugf("error while tracing process: %v", err)
		return nil, err
	}

	r.ExitCode = pctx.exitCode

	if pctx.exitCode != 0 {
		return pctx.procInfoArray(), fmt.Errorf("exit status %v", pctx.exitCode)
	}

	return pctx.procInfoArray(), nil
}

func (p *ptraceContext) runTrace() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	status := unix.WaitStatus(0)
	_, err := unix.Wait4(p.parentPid, &status, 0, nil)
	if err != nil {
		return err
	}

	if err := unix.PtraceSetOptions(p.parentPid, unix.PTRACE_O_TRACESYSGOOD|unix.PTRACE_O_TRACEEXEC|unix.PTRACE_O_TRACEEXIT|unix.PTRACE_O_TRACEVFORK|unix.PTRACE_O_TRACEFORK|unix.PTRACE_O_TRACECLONE); err != nil {
		return err
	}

	procInfo := p.getProcInfo(p.parentPid)
	procInfo.Program = p.mainProgram
	if err := unix.PtraceSyscall(p.parentPid, 0); err != nil {
		return err
	}

	for {
		pid, err := unix.Wait4(-1, &status, unix.WALL, nil)
		if err != nil {
			return err
		}
		if pid == p.parentPid && status.Exited() {
			p.exitCode = status.ExitStatus()
			return nil
		}

		sig := status.StopSignal()
		// since we set PTRACE_O_TRACESYSGOOD any traps triggered by ptrace will have its signal set to SIGTRAP|0x80.
		// If we catch a signal that isn't a ptrace'd signal we want to let the process continue to handle that signal, so we inject the thrown signal back to the process.
		// If it was a ptrace SIGTRAP we suppress the signal and send 0
		injectedSig := int(sig)
		isPtraceTrap := (unix.SIGTRAP | unix.PTRACE_EVENT_STOP) == sig
		if status.Stopped() && isPtraceTrap {
			injectedSig = 0
			if err := p.nextSyscall(pid); err != nil {
				log.Debugf("(tracing) got error while processing syscall: %v", err)
			}
		}

		if err := unix.PtraceSyscall(pid, injectedSig); err != nil {
			log.Debugf("(tracing) got error from ptrace syscall: %v", err)
		}
	}
}

// nextSyscall handles the next system call for the given process ID.
func (p *ptraceContext) nextSyscall(pid int) error {
	regs := unix.PtraceRegs{}

	if err := unix.PtraceGetRegs(pid, &regs); err != nil {
		return err
	}

	msg, err := unix.PtraceGetEventMsg(pid)
	if err != nil {
		return err
	}

	if msg == unix.PTRACE_EVENTMSG_SYSCALL_EXIT {
		if err := p.handleSyscallExit(pid, regs); err != nil {
			return err
		}
	}

	if msg == unix.PTRACE_EVENTMSG_SYSCALL_ENTRY {
		if err := p.handleSyscallEnter(pid, regs); err != nil {
			return err
		}
	}

	return nil
}

func (p *ptraceContext) handleExeCve(pid int, argArray []uintptr) error {
	procInfo := p.getProcInfo(pid)

	program, err := p.readSyscallReg(pid, argArray[0], MAX_PATH_LEN)
	if err == nil {
		procInfo.Program = program
	}

	exeLocation := fmt.Sprintf("/proc/%d/exe", procInfo.ProcessID)
	exeLocation, err = filepath.EvalSymlinks(exeLocation)
	if err != nil {
		return err
	}

	commLocation := fmt.Sprintf("/proc/%d/comm", procInfo.ProcessID)
	commLocation, err = filepath.EvalSymlinks(commLocation)
	if err != nil {
		return err
	}

	envinLocation := fmt.Sprintf("/proc/%d/environ", procInfo.ProcessID)
	envinLocation, err = filepath.EvalSymlinks(envinLocation)
	if err != nil {
		return err
	}

	cmdlineLocation := fmt.Sprintf("/proc/%d/cmdline", procInfo.ProcessID)
	cmdlineLocation, err = filepath.EvalSymlinks(cmdlineLocation)
	if err != nil {
		return err
	}

	status := fmt.Sprintf("/proc/%d/status", procInfo.ProcessID)
	status, err = filepath.EvalSymlinks(status)
	if err != nil {
		return err
	}

	// read status file and set attributes on success
	statusFile, err := os.ReadFile(status)
	if err == nil {
		ppid, err := getPPIDFromStatus(statusFile)
		if err == nil {
			procInfo.ParentPID = ppid
		}
	}

	comm, err := os.ReadFile(commLocation)
	if err == nil {
		procInfo.Comm = cleanString(string(comm))
	}

	//create map for env vars
	procInfo.Environ = make(map[string]string)

	//get env vars for process

	environ, err := os.ReadFile(envinLocation)

	if err == nil {
		allVars := strings.Split(string(environ), "\x00")
		filteredEnviron := make([]string, 0)
		environment.FilterEnvironmentArray(allVars, p.environmentBlockList, func(_, _, varStr string) {
			filteredEnviron = append(filteredEnviron, varStr)
		})

		parentEnvs := p.processes[procInfo.ParentPID].Environ
		if parentEnvs == nil {
			parentEnvs = make(map[string]string)
		}

		// Check which environment variables are new and add them to procInfo.Environ
		for _, varStr := range filteredEnviron {

			//guard out of bounds
			if len(strings.Split(varStr, "=")) < 2 {
				continue
			}

			key := strings.Split(varStr, "=")[0]
			value := strings.Split(varStr, "=")[1]

			if _, ok := parentEnvs[key]; !ok {
				procInfo.Environ[key] = value

			}
		}
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

	return nil
}

func (p *ptraceContext) handleOpenedFile(pid int, argArray []uintptr) error {
	fileName, err := p.readSyscallReg(pid, argArray[1], MAX_PATH_LEN)
	if err != nil {
		return err
	}

	procInfo := p.getProcInfo(pid)

	file, err := filepath.EvalSymlinks(fileName)
	//record that the process tried to open the file, even if it doesn't exist
	if err != nil && os.IsNotExist(err) {
		procInfo.OpenedFiles[fileName] = cryptoutil.DigestSet{}
		return nil
	}
	if err != nil {
		return err
	}

	//switch on file type
	fileInfo, err := os.Stat(file)
	if err != nil {
		return err
	}

	ds := cryptoutil.DigestSet{}

	//if it's a directory, we don't want to hash it
	if fileInfo.IsDir() {
		procInfo.OpenedFiles[file] = ds
		return nil
	}

	//if it s special file, we don't want to hash it
	if fileInfo.Mode()&os.ModeDevice != 0 {
		procInfo.OpenedFiles[file] = ds
		return nil
	}

	digestSet, err := cryptoutil.CalculateDigestSetFromFile(file, p.hash)
	if err != nil {
		return err
	}
	procInfo.OpenedFiles[file] = digestSet

	return nil
}

type SocketAddress struct {
	Family uint16
	Port   uint16
	Addr   [4]byte
}

func (p *ptraceContext) handleConnectedSocket(pid int, argArray []uintptr) error {
	procInfo := p.getProcInfo(pid)

	// Get the file descriptor and sockaddr information
	fd := int(argArray[0])
	sockaddrPtr := argArray[1]
	sockaddrLen := int(argArray[2])

	// Read the sockaddr structure from the traced process's memory
	sockaddrBytes, err := p.readSyscallData(pid, uintptr(sockaddrPtr), sockaddrLen)
	if err != nil {
		return err
	}

	// Parse the sockaddr structure
	var sa SocketAddress
	if err := binary.Read(bytes.NewReader(sockaddrBytes), binary.LittleEndian, &sa); err != nil {
		return err
	}

	// Get protocol and domain
	var protocol string
	switch sa.Family {
	case syscall.AF_INET:
		protocol = "tcp"
	case syscall.AF_INET6:
		protocol = "tcp6"
	case syscall.AF_UNIX:
		protocol = "unix"
	default:
		return fmt.Errorf("unsupported protocol family %d", sa.Family)
	}

	// Get remote address and port
	var addr string
	if sa.Family == syscall.AF_UNIX {
		path := string(sa.Addr[:])
		if filepath.IsAbs(path) {
			// Ensure the path is not empty
			if len(path) > 0 && path[0] == '\x00' {
				path = path[1:]
			}
			path, err = filepath.EvalSymlinks(path)
			if err != nil {
				return err
			}
		}
		addr = path
	} else {
		addr = fmt.Sprintf("%d.%d.%d.%d", sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3])
	}

	port := int(sa.Port)

	// Record the remote address and port
	connInfo := ConnectionInfo{Protocol: protocol, Address: addr, Port: port}

	// Retrieve the SocketInfo value from the map
	socketID, err := getSocketKey(pid, fd)
	if err != nil {
		return err
	}

	sockets := make(map[int]SocketInfo)

	socketInfo, ok := procInfo.Sockets[socketID]
	if !ok {

		socketInfo = SocketInfo{
			Type:        "",
			Protocol:    protocol,
			Fd:          fd,
			Connections: []ConnectionInfo{connInfo},
		}

		// Modify the Connections field
		socketInfo.Connections = append(socketInfo.Connections, connInfo)

		// merge the socket info back into the map
		procInfo.Sockets = sockets

	} else {
		// Modify the Connections field
		socketInfo.Connections = append(socketInfo.Connections, connInfo)
	}

	procInfo.Sockets[socketID] = socketInfo

	return nil
}

func (p *ptraceContext) handleSendMsg(pid int, argArray []uintptr) error {
	procInfo := p.getProcInfo(pid)

	// Get the file descriptor
	fd := int(argArray[0])

	// Get the iovec structure
	//msgPtr := argArray[1]
	//msghdr, err := p.readMsghdr(pid, uintptr(msgPtr))
	// if err != nil {
	// 	return err
	// }

	// Get the sockaddr structure

	// Get the number of bytes sent
	bytesSent := int(argArray[2])
	fmt.Printf("\n\nbytes sent: %d\n\n", bytesSent)

	// Record the number of bytes sent
	connInfo := ConnectionInfo{Bytes: bytesSent}

	// Retrieve the SocketInfo value from the map
	socketID, err := getSocketKey(pid, fd)
	if err != nil {
		return err
	}

	socketInfo, ok := procInfo.Sockets[socketID]
	if !ok {
		socketInfo = SocketInfo{}
	}

	// Modify the Connections field
	socketInfo.Connections = append(socketInfo.Connections, connInfo)

	// Store the modified SocketInfo back in the map guard against nil map
	if procInfo.Sockets == nil {
		procInfo.Sockets = make(map[int]SocketInfo)
	}

	procInfo.Sockets[socketID] = socketInfo

	return nil
}

func (p *ptraceContext) handleSyscallExit(pid int, regs unix.PtraceRegs) error {
	syscallId := getSyscallId(regs)
	argArray := getSyscallArgs(regs)

	switch syscallId {
	case unix.SYS_SOCKET:
		if err := p.handleConnectedSocket(pid, argArray); err != nil {
			return err
		}
	}
	return nil

}

func (p *ptraceContext) handleSyscallEnter(pid int, regs unix.PtraceRegs) error {
	argArray := getSyscallArgs(regs)
	syscallId := getSyscallId(regs)

	switch syscallId {
	case unix.SYS_EXECVE:
		if err := p.handleExeCve(pid, argArray); err != nil {
			return err
		}

	case unix.SYS_OPENAT:
		if err := p.handleOpenedFile(pid, argArray); err != nil {
			return err
		}

	case unix.SYS_CONNECT:
		if err := p.handleConnectedSocket(pid, argArray); err != nil {
			return err
		}
	case unix.SYS_SENDTO:
		if err := p.handleSendMsg(pid, argArray); err != nil {
			return err
		}
	case unix.SYS_SENDMSG:
		log.Debugf("syscall: SYS_SENDMSG (pid: %d)", pid)
		if err := p.handleSendMsg(pid, argArray); err != nil {
			return err
		}
	}
	return nil
}

func (p *ptraceContext) hadleSocket(pid int, argArray []uintptr) error {
	// Refactored code
	socketFd := argArray[0]
	socketType := argArray[1]
	socketProtocol := argArray[2]

	socketTypeStr := intToString(int(socketType), socketTypeMap)
	socketProtocolStr := intToString(int(socketProtocol), socketProtocolMap)

	procInfo := p.getProcInfo(pid)

	si := SocketInfo{
		Type:        socketTypeStr,
		Protocol:    socketProtocolStr,
		Fd:          int(socketFd),
		Connections: []ConnectionInfo{},
	}

	// Add the new socket to the map
	socketID, err := getSocketKey(pid, int(socketFd))
	if err != nil {
		return err
	}
	procInfo.Sockets[socketID] = si

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
	return strings.TrimSpace(strings.Replace(s, "\x00", " ", -1))
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

func (p *ptraceContext) readSyscallData(pid int, addr uintptr, size int) ([]byte, error) {
	buf := make([]byte, size)
	n := 0
	for n < size {
		word := make([]byte, WORD_SIZE)
		_, err := unix.PtracePeekData(pid, uintptr(addr)+uintptr(n), word)
		if err != nil {
			return nil, err
		}

		// copy the word into the output buffer, taking care not to over-read
		bytesToCopy := size - n
		if bytesToCopy > WORD_SIZE {
			bytesToCopy = WORD_SIZE
		}
		copy(buf[n:n+bytesToCopy], word[:bytesToCopy])

		n += bytesToCopy
	}

	return buf, nil
}

func getSocketKey(pid int, fd int) (int, error) {
	key, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
	if err != nil {
		return 0, err
	}

	socketIdStr := strings.TrimPrefix(key, "socket:[")
	socketIdStr = strings.TrimSuffix(socketIdStr, "]")

	socketId, err := strconv.Atoi(socketIdStr)
	if err != nil {
		return 0, err
	}

	return socketId, nil

}

func intToString(value int, m map[int]string) string {
	if str, ok := m[value]; ok {
		return str
	}
	return "UNKNOWN"
}

var socketTypeMap = map[int]string{
	unix.SOCK_STREAM:    "SOCK_STREAM",
	unix.SOCK_DGRAM:     "SOCK_DGRAM",
	unix.SOCK_RAW:       "SOCK_RAW",
	unix.SOCK_RDM:       "SOCK_RDM",
	unix.SOCK_SEQPACKET: "SOCK_SEQPACKET",
	unix.SOCK_DCCP:      "SOCK_DCCP",
	unix.SOCK_PACKET:    "SOCK_PACKET",
}

var socketProtocolMap = map[int]string{
	unix.IPPROTO_IP:      "IPPROTO_IP",
	unix.IPPROTO_ICMP:    "IPPROTO_ICMP",
	unix.IPPROTO_IGMP:    "IPPROTO_IGMP",
	unix.IPPROTO_IPIP:    "IPPROTO_IPIP",
	unix.IPPROTO_TCP:     "IPPROTO_TCP",
	unix.IPPROTO_EGP:     "IPPROTO_EGP",
	unix.IPPROTO_PUP:     "IPPROTO_PUP",
	unix.IPPROTO_UDP:     "IPPROTO_UDP",
	unix.IPPROTO_IDP:     "IPPROTO_IDP",
	unix.IPPROTO_TP:      "IPPROTO_TP",
	unix.IPPROTO_DCCP:    "IPPROTO_DCCP",
	unix.IPPROTO_IPV6:    "IPPROTO_IPV6",
	unix.IPPROTO_RSVP:    "IPPROTO_RSVP",
	unix.IPPROTO_GRE:     "IPPROTO_GRE",
	unix.IPPROTO_ESP:     "IPPROTO_ESP",
	unix.IPPROTO_AH:      "IPPROTO_AH",
	unix.IPPROTO_MTP:     "IPPROTO_MTP",
	unix.IPPROTO_BEETPH:  "IPPROTO_BEETPH",
	unix.IPPROTO_ENCAP:   "IPPROTO_ENCAP",
	unix.IPPROTO_PIM:     "IPPROTO_PIM",
	unix.IPPROTO_COMP:    "IPPROTO_COMP",
	unix.IPPROTO_SCTP:    "IPPROTO_SCTP",
	unix.IPPROTO_UDPLITE: "IPPROTO_UDPLITE",
	unix.IPPROTO_MPLS:    "IPPROTO_MPLS",
	unix.IPPROTO_RAW:     "IPPROTO_RAW",
}
