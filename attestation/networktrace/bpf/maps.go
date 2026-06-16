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
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
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

// Gate-protocol constants. These mirror the values in headers/common.h.
const (
	proxyNotReady uint8 = 0
	proxyReady    uint8 = 1
)

// FrozenTask describes a process that the namespace gate has SIGSTOP'd and that is
// awaiting a SIGCONT once a proxy is ready for its namespace.
type FrozenTask struct {
	NetnsInum uint32
	NsTID     uint32
	HostTID   uint32
	StopTsNs  uint64
}

// SetProxyReady marks a network namespace as having a ready proxy. This is the
// monotonic latch the namespace gate reads: it MUST be called before sweeping the
// gate for that namespace so the publish-before-recheck barrier holds.
func (m *Maps) SetProxyReady(netnsInum uint32) error {
	key := gateProxyStateKey(netnsInum)
	val := proxyReady
	if err := m.ProxyStateMap.Put(&key, &val); err != nil {
		return fmt.Errorf("set proxy_state ready for netns %d: %w", netnsInum, err)
	}
	return nil
}

// IsProxyReady reports whether a namespace has already been marked ready.
func (m *Maps) IsProxyReady(netnsInum uint32) bool {
	key := gateProxyStateKey(netnsInum)
	var val uint8
	if err := m.ProxyStateMap.Lookup(&key, &val); err != nil {
		return false
	}
	return val == proxyReady
}

// SetTracingDisabled flips the global kill switch. Still records witness pid namespace level.
func (m *Maps) SetTracingDisabled(disabled bool) error {
	var key uint32 // single-element ARRAY map, index 0
	val := task_trackerControlVal{}
	if disabled {
		val.TracingDisabled = 1
	}
	if err := m.ControlMap.Put(&key, &val); err != nil {
		return fmt.Errorf("set control_map tracing_disabled=%v: %w", disabled, err)
	}
	return nil
}

// DrainGate consumes every pending gate entry (optionally limited to a single
// namespace when onlyNetns != 0) and invokes wake for each. wake is expected to
// deliver SIGCONT; an error from wake does not stop the drain (we must never leave a task frozen).
func (m *Maps) DrainGate(onlyNetns uint32, wake func(FrozenTask) error) error {
	var (
		key     task_trackerGateKey
		val     task_trackerGateVal
		entries []FrozenTask
	)

	iter := m.GateMap.Iterate()
	for iter.Next(&key, &val) {
		if onlyNetns != 0 && key.NetnsInum != onlyNetns {
			continue
		}
		entries = append(entries, FrozenTask{
			NetnsInum: key.NetnsInum,
			NsTID:     key.Tid,
			HostTID:   val.HostTid,
			StopTsNs:  val.StopTsNs,
		})
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate gate_map: %w", err)
	}

	var firstErr error
	for _, e := range entries {
		k := task_trackerGateKey{NetnsInum: e.NetnsInum, Tid: e.NsTID}
		var consumed task_trackerGateVal
		if err := m.GateMap.LookupAndDelete(&k, &consumed); err != nil {
			// Already consumed by another sweep/watchdog pass; skip.
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			if firstErr == nil {
				firstErr = err
			}
			// Still attempt to wake to avoid stranding.
		}
		if err := wake(e); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// SnapshotGate returns the current set of frozen tasks without consuming them.
// Used by the watchdog to detect stalls.
func (m *Maps) SnapshotGate() ([]FrozenTask, error) {
	var (
		key     task_trackerGateKey
		val     task_trackerGateVal
		entries []FrozenTask
	)
	iter := m.GateMap.Iterate()
	for iter.Next(&key, &val) {
		entries = append(entries, FrozenTask{
			NetnsInum: key.NetnsInum,
			NsTID:     key.Tid,
			HostTID:   val.HostTid,
			StopTsNs:  val.StopTsNs,
		})
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate gate_map: %w", err)
	}
	return entries, nil
}

// ClearInterceptionMaps empties every map that drives interception so that the
// connect/sockops hooks stop redirecting traffic and in-flight proxied
// connections drain to zero (allowing the proxy goroutine to exit). Used during
// fail-closed teardown, AFTER the gate has been drained and tracing disabled.
// The race between snapshotting the map and deleting elements is acceptable
// as global proxy switch is also turned off.
func (m *Maps) ClearInterceptionMaps() error {
	var errs []error
	clearMapWithName := func(name string, mp *ebpf.Map) {
		if mp == nil {
			return
		}
		if err := clearMap(mp); err != nil {
			errs = append(errs, fmt.Errorf("clear %s: %w", name, err))
		}
	}
	clearMapWithName("witness_pid_ns_tid_allowlist", m.WitnessPidNsTIDAllowlist)
	clearMapWithName("comm_allowlist", m.CommAllowlist)
	clearMapWithName("cgroup_allowlist", m.CgroupAllowlist)
	clearMapWithName("orig_dst_map", m.OrigDstMap)
	clearMapWithName("orig_dst_map_v6", m.OrigDstMapV6)
	clearMapWithName("tuple_to_cookie_map", m.TupleCookieMap)
	clearMapWithName("tuple_to_cookie_map_v6", m.TupleCookieMapV6)
	clearMapWithName("proxy_state_map", m.ProxyStateMap)
	clearMapWithName("tracked_pid_ns_map", m.TrackedPidNsMap)
	clearMapWithName("witness_pid_ns_level_map", m.WitnessPidNsLevelMap)
	return errors.Join(errs...)
}

// clearMap deletes every key in a hash map. Keys are snapshotted first because
// deleting during iteration is not safe.
func clearMap(mp *ebpf.Map) error {
	var keys [][]byte
	var key []byte
	val := make([]byte, mp.ValueSize())
	iter := mp.Iterate()
	for iter.Next(&key, &val) {
		k := make([]byte, len(key))
		copy(k, key)
		keys = append(keys, k)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, k := range keys {
		if err := mp.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}

func gateProxyStateKey(netnsInum uint32) task_trackerProxyStateKey {
	return task_trackerProxyStateKey{NetnsInum: netnsInum}
}

// SendSIGCONT delivers SIGCONT to the given host TID. ESRCH (task already gone)
// is treated as success.
func SendSIGCONT(hostTID uint32) error {
	if err := unix.Kill(int(hostTID), unix.SIGCONT); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return nil
		}
		return fmt.Errorf("SIGCONT tid %d: %w", hostTID, err)
	}
	return nil
}
