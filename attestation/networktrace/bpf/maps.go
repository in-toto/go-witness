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

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	MaxCommLen = 16
)

// Helper functions for working with the bpf2go generated types

// GetOrigIP returns the original IP as net.IP from connectOrigDstVal
func (o *connectOrigDstVal) GetOrigIP() net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, o.OrigIp)
	return ip
}

// GetOrigIP returns the original IPv6 address from connectOrigDstValV6
func (o *connectOrigDstValV6) GetOrigIP() net.IP {
	return net.IP(o.OrigIp[:])
}

// GetComm returns the process name from connectOrigDstVal
func (o *connectOrigDstVal) GetComm() string {
	return int8SliceToString(o.Comm[:])
}

// GetComm returns the process name from connectOrigDstValV6
func (o *connectOrigDstValV6) GetComm() string {
	return int8SliceToString(o.Comm[:])
}

// int8SliceToString converts a null-terminated int8 slice to string
func int8SliceToString(s []int8) string {
	var b []byte
	for _, v := range s {
		if v == 0 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}

// StringToCommInt8 converts a string to a fixed-size int8 array for comm fields
func StringToCommInt8(s string) [MaxCommLen]int8 {
	var comm [MaxCommLen]int8
	for i := 0; i < len(s) && i < MaxCommLen; i++ {
		comm[i] = int8(s[i])
	}
	return comm
}

// ConnectionMetadata contains all metadata about a connection
type ConnectionMetadata struct {
	SockCookie uint64
	PID        uint32
	CgroupID   uint64
	Comm       string
	OrigIP     net.IP
	OrigPort   uint16
}

// String returns a human-readable representation
func (m *ConnectionMetadata) String() string {
	return fmt.Sprintf("pid=%d comm=%s (orig: %s:%d) cgroup=%d",
		m.PID, m.Comm, m.OrigIP, m.OrigPort, m.CgroupID)
}

// ToConnectionMetadata converts a connectOrigDstVal to ConnectionMetadata
func (o *connectOrigDstVal) ToConnectionMetadata(cookie uint64) *ConnectionMetadata {
	return &ConnectionMetadata{
		SockCookie: cookie,
		PID:        o.Pid,
		CgroupID:   o.CgroupId,
		Comm:       o.GetComm(),
		OrigIP:     o.GetOrigIP(),
		OrigPort:   o.OrigPort,
	}
}

// ToConnectionMetadata converts a connectOrigDstValV6 to ConnectionMetadata
func (o *connectOrigDstValV6) ToConnectionMetadata(cookie uint64) *ConnectionMetadata {
	return &ConnectionMetadata{
		SockCookie: cookie,
		PID:        o.Pid,
		CgroupID:   o.CgroupId,
		Comm:       o.GetComm(),
		OrigIP:     o.GetOrigIP(),
		OrigPort:   o.OrigPort,
	}
}
