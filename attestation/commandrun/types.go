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

package commandrun

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Custom types for better type safety

// PID represents a process ID
type PID int

// MarshalJSON implements json.Marshaler
func (p PID) MarshalJSON() ([]byte, error) {
	return json.Marshal(int(p))
}

// UnmarshalJSON implements json.Unmarshaler
func (p *PID) UnmarshalJSON(data []byte) error {
	var i int
	if err := json.Unmarshal(data, &i); err != nil {
		return err
	}
	*p = PID(i)
	return nil
}

// FileDescriptor represents a file descriptor
type FileDescriptor int

// Define standard file descriptors
const (
	Stdin  FileDescriptor = 0
	Stdout FileDescriptor = 1
	Stderr FileDescriptor = 2
)

// SocketDomain represents socket address families
type SocketDomain int

const (
	DomainUnknown SocketDomain = iota
	DomainUnix
	DomainInet
	DomainInet6
	DomainNetlink
)

func (d SocketDomain) String() string {
	switch d {
	case DomainUnix:
		return "AF_UNIX"
	case DomainInet:
		return "AF_INET"
	case DomainInet6:
		return "AF_INET6"
	case DomainNetlink:
		return "AF_NETLINK"
	default:
		return fmt.Sprintf("AF_%d", d)
	}
}

// SocketType represents socket types
type SocketType int

const (
	SocketUnknown SocketType = iota
	SocketStream
	SocketDgram
	SocketRaw
	SocketSeqPacket
)

func (t SocketType) String() string {
	switch t {
	case SocketStream:
		return "SOCK_STREAM"
	case SocketDgram:
		return "SOCK_DGRAM"
	case SocketRaw:
		return "SOCK_RAW"
	case SocketSeqPacket:
		return "SOCK_SEQPACKET"
	default:
		return fmt.Sprintf("SOCK_%d", t)
	}
}

// Protocol represents network protocols
type Protocol int

const (
	ProtocolDefault Protocol = 0
	ProtocolTCP     Protocol = 6
	ProtocolUDP     Protocol = 17
	ProtocolICMP    Protocol = 1
	ProtocolICMPv6  Protocol = 58
)

func (p Protocol) String() string {
	switch p {
	case ProtocolDefault:
		return "default"
	case ProtocolTCP:
		return "tcp"
	case ProtocolUDP:
		return "udp"
	case ProtocolICMP:
		return "icmp"
	case ProtocolICMPv6:
		return "icmpv6"
	default:
		return fmt.Sprintf("proto_%d", p)
	}
}

// ConnectionType represents the type of network connection
type ConnectionType string

const (
	ConnectionConnect ConnectionType = "connect"
	ConnectionBind    ConnectionType = "bind"
	ConnectionListen  ConnectionType = "listen"
	ConnectionAccept  ConnectionType = "accept"
)

// FileAccessType represents how a file was accessed
type FileAccessType int

const (
	FileAccessRead FileAccessType = iota
	FileAccessWrite
	FileAccessCreate
	FileAccessDelete
)

func (t FileAccessType) String() string {
	switch t {
	case FileAccessRead:
		return "read"
	case FileAccessWrite:
		return "write"
	case FileAccessCreate:
		return "create"
	case FileAccessDelete:
		return "delete"
	default:
		return "unknown"
	}
}

// ProcessState represents the state of a process
type ProcessState int

const (
	ProcessRunning ProcessState = iota
	ProcessStopped
	ProcessExited
	ProcessZombie
)

// ResourceLimits represents configurable limits for tracing
type ResourceLimits struct {
	MaxProcesses     int           // Maximum number of processes to trace
	MaxFileSize      int64         // Maximum file size to hash
	MaxTraceTime     time.Duration // Maximum time to trace
	MaxMemoryPerProc uint64        // Maximum memory per process before warning
}

// DefaultResourceLimits returns sensible defaults
func DefaultResourceLimits() ResourceLimits {
	return ResourceLimits{
		MaxProcesses:     1000,
		MaxFileSize:      100 * 1024 * 1024, // 100MB
		MaxTraceTime:     30 * time.Minute,
		MaxMemoryPerProc: 1024 * 1024 * 1024, // 1GB
	}
}

// Custom errors for better error handling

var (
	// ErrTracingNotSupported indicates platform doesn't support tracing
	ErrTracingNotSupported = errors.New("tracing not supported on this platform")
	
	// ErrProcessNotFound indicates a process doesn't exist
	ErrProcessNotFound = errors.New("process not found")
	
	// ErrPermissionDenied indicates insufficient permissions
	ErrPermissionDenied = errors.New("permission denied")
	
	// ErrResourceLimit indicates a resource limit was hit
	ErrResourceLimit = errors.New("resource limit exceeded")
)

// TracerError provides structured error information
type TracerError struct {
	Op      string // Operation that failed
	PID     PID    // Process ID involved
	Syscall string // System call if applicable
	Err     error  // Underlying error
}

func (e *TracerError) Error() string {
	if e.Syscall != "" {
		return fmt.Sprintf("%s: pid=%d syscall=%s: %v", e.Op, e.PID, e.Syscall, e.Err)
	}
	return fmt.Sprintf("%s: pid=%d: %v", e.Op, e.PID, e.Err)
}

func (e *TracerError) Unwrap() error {
	return e.Err
}

// NetworkAddress wraps network address information
type NetworkAddress struct {
	Network string // "tcp", "udp", "unix"
	Address string // IP:port or path
	IP      net.IP // Parsed IP if applicable
	Port    int    // Parsed port if applicable
}

func ParseNetworkAddress(network, address string) (*NetworkAddress, error) {
	na := &NetworkAddress{
		Network: network,
		Address: address,
	}
	
	if network == "unix" {
		return na, nil
	}
	
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("parsing address %q: %w", address, err)
	}
	
	na.IP = net.ParseIP(host)
	if na.IP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", host)
	}
	
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return nil, fmt.Errorf("invalid port: %s", portStr)
	}
	na.Port = port
	
	return na, nil
}

// ProcessTree provides efficient process hierarchy operations
type ProcessTree struct {
	processes map[PID]*ProcessInfo
	children  map[PID][]PID
	root      PID
}

func NewProcessTree() *ProcessTree {
	return &ProcessTree{
		processes: make(map[PID]*ProcessInfo),
		children:  make(map[PID][]PID),
	}
}

func (pt *ProcessTree) AddProcess(info *ProcessInfo) {
	pid := PID(info.ProcessID)
	ppid := PID(info.ParentPID)
	
	pt.processes[pid] = info
	
	if ppid != 0 {
		pt.children[ppid] = append(pt.children[ppid], pid)
	} else if pt.root == 0 {
		pt.root = pid
	}
}

func (pt *ProcessTree) GetProcess(pid PID) (*ProcessInfo, bool) {
	p, ok := pt.processes[pid]
	return p, ok
}

func (pt *ProcessTree) GetChildren(pid PID) []PID {
	return pt.children[pid]
}

func (pt *ProcessTree) Walk(fn func(PID, *ProcessInfo) error) error {
	var walkNode func(PID) error
	walkNode = func(pid PID) error {
		if proc, ok := pt.processes[pid]; ok {
			if err := fn(pid, proc); err != nil {
				return err
			}
		}
		
		for _, child := range pt.children[pid] {
			if err := walkNode(child); err != nil {
				return err
			}
		}
		return nil
	}
	
	return walkNode(pt.root)
}

// Helper functions

// IsSpecialPath checks if a path should be ignored
func IsSpecialPath(path string) bool {
	return strings.HasPrefix(path, "/proc/") ||
		strings.HasPrefix(path, "/dev/") ||
		strings.HasPrefix(path, "/sys/")
}

// ValidateTracerOptions ensures options are valid
func ValidateTracerOptions(opts TracerOptions) error {
	// Add validation logic as needed
	return nil
}