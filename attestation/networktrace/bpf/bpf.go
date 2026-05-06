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
	"io"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/in-toto/go-witness/attestation/networktrace/types"
	"golang.org/x/sys/unix"
)

// LoadConfig holds the configuration needed to load BPF programs.
type LoadConfig struct {
	CgroupPath string
	ProxyPort  uint16
	ProxyIPv4  string
}

// State holds all BPF objects (programs, maps, links) whose lifetimes are
// tied to this process. When State.Close() is called (or the process exits),
// the kernel automatically detaches and garbage-collects the BPF programs
// and maps because no more file descriptors reference them.
type State struct {
	Maps *Maps

	// closers keeps every object that must be closed on teardown.
	// Order: links first, then programs, then maps.
	closers []io.Closer
}

// Close releases all BPF resources in reverse-creation order.
func (s *State) Close() error {
	var errs []error
	for i := len(s.closers) - 1; i >= 0; i-- {
		if err := s.closers[i].Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("errors closing bpf state: %v", errs)
	}
	return nil
}

func GetCurrentNetns() (uint32, error) {
	var stat unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &stat); err != nil {
		return 0, fmt.Errorf("stat /proc/self/ns/net: %w", err)
	}
	return uint32(stat.Ino), nil
}

func ipToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP address: %s", ipStr)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("not an IPv4 address: %s", ipStr)
	}
	return binary.BigEndian.Uint32(ip4), nil
}

// Load loads and attaches BPF programs using embedded bytecode from bpf2go.
// Programs and maps are NOT pinned to the BPF filesystem; their lifetime is
// tied to the returned State. Call State.Close() to detach and release everything.
// If the process dies without calling Close(), the kernel will automatically
// clean up because there are no pinned references.
func Load(cfg LoadConfig) (*State, error) {
	// Required to load bpf programs on some kernel versions
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	hostNetnsInum, err := GetCurrentNetns()
	if err != nil {
		return nil, fmt.Errorf("get current netns: %w", err)
	}

	proxyPort := cfg.ProxyPort
	if proxyPort == 0 {
		proxyPort = types.DefaultProxyPort
	}
	proxyIP := cfg.ProxyIPv4
	if proxyIP == "" {
		proxyIP = types.DefaultProxyBindIPv4
	}

	proxyIPUint32, err := ipToUint32(proxyIP)
	if err != nil {
		return nil, fmt.Errorf("convert proxy IP: %w", err)
	}

	connectSpec, err := loadConnect()
	if err != nil {
		return nil, fmt.Errorf("load connect spec: %w", err)
	}

	if err := connectSpec.Variables["proxy_port"].Set(uint32(proxyPort)); err != nil {
		return nil, fmt.Errorf("set proxy_port in connect: %w", err)
	}
	if err := connectSpec.Variables["proxy_ip"].Set(proxyIPUint32); err != nil {
		return nil, fmt.Errorf("set proxy_ip in connect: %w", err)
	}
	if err := connectSpec.Variables["host_netns_inum"].Set(hostNetnsInum); err != nil {
		return nil, fmt.Errorf("set host_netns_inum in connect: %w", err)
	}

	var connectObjs connectObjects
	if err := connectSpec.LoadAndAssign(&connectObjs, nil); err != nil {
		return nil, fmt.Errorf("load connect objects: %w", err)
	}

	sockopsSpec, err := loadSockops()
	if err != nil {
		connectObjs.Close()
		return nil, fmt.Errorf("load sockops spec: %w", err)
	}

	if err := sockopsSpec.Variables["host_netns_inum"].Set(hostNetnsInum); err != nil {
		connectObjs.Close()
		return nil, fmt.Errorf("set host_netns_inum in sockops: %w", err)
	}

	sockopsOpts := ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"orig_dst_map":           connectObjs.OrigDstMap,
			"orig_dst_map_v6":        connectObjs.OrigDstMapV6,
			"pid_allowlist":          connectObjs.PidAllowlist,
			"comm_allowlist":         connectObjs.CommAllowlist,
			"cgroup_allowlist":       connectObjs.CgroupAllowlist,
			"injection_time_map":     connectObjs.InjectionTimeMap,
			"tuple_to_cookie_map":    connectObjs.TupleToCookieMap,
			"tuple_to_cookie_map_v6": connectObjs.TupleToCookieMapV6,
		},
	}

	var sockopsObjs sockopsObjects
	if err := sockopsSpec.LoadAndAssign(&sockopsObjs, &sockopsOpts); err != nil {
		connectObjs.Close()
		return nil, fmt.Errorf("load sockops objects: %w", err)
	}

	type progAttachment struct {
		prog       *ebpf.Program
		name       string
		attachType ebpf.AttachType
	}

	attachments := []progAttachment{
		{connectObjs.InterceptConnect4, "connect4", ebpf.AttachCGroupInet4Connect},
		{connectObjs.InterceptConnect6, "connect6", ebpf.AttachCGroupInet6Connect},
		{sockopsObjs.TcpSockops, "sockops", ebpf.AttachCGroupSockOps},
	}

	// closers are appended in creation order so that
	// Close() can tear them down in reverse (links first, then progs/maps).
	state := &State{
		Maps: &Maps{
			OrigDstMap:       connectObjs.OrigDstMap,
			OrigDstMapV6:     connectObjs.OrigDstMapV6,
			PIDAllowlist:     connectObjs.PidAllowlist,
			CommAllowlist:    connectObjs.CommAllowlist,
			CgroupAllowlist:  connectObjs.CgroupAllowlist,
			InjectionTimeMap: connectObjs.InjectionTimeMap,
			TupleCookieMap:   connectObjs.TupleToCookieMap,
			TupleCookieMapV6: connectObjs.TupleToCookieMapV6,
		},
	}

	// Track programs for closing (maps are already referenced via Maps struct
	// and will be closed by connectObjs/sockopsObjs closers)
	state.closers = append(state.closers, &connectObjs, &sockopsObjs)

	for _, att := range attachments {
		if att.prog == nil {
			state.Close()
			return nil, fmt.Errorf("program not found for %s", att.name)
		}

		// All cgroups in the subtree will also be traced
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cfg.CgroupPath,
			Attach:  att.attachType,
			Program: att.prog,
		})
		if err != nil {
			state.Close()
			return nil, fmt.Errorf("attach %s: %w", att.name, err)
		}

		state.closers = append(state.closers, l)
	}

	return state, nil
}

// Maps holds references to BPF maps with typed accessor methods.
type Maps struct {
	OrigDstMap       *ebpf.Map
	OrigDstMapV6     *ebpf.Map
	PIDAllowlist     *ebpf.Map
	CommAllowlist    *ebpf.Map
	CgroupAllowlist  *ebpf.Map
	InjectionTimeMap *ebpf.Map
	TupleCookieMap   *ebpf.Map
	TupleCookieMapV6 *ebpf.Map
}

// LookupOrigDst looks up original destination metadata for an IPv4 connection by socket cookie.
func (m *Maps) LookupOrigDst(sockCookie uint64) (*ConnectionMetadata, error) {
	key := connectOrigDstKey{SockCookie: sockCookie}
	var val connectOrigDstVal
	if err := m.OrigDstMap.Lookup(&key, &val); err != nil {
		return nil, err
	}
	return val.ToConnectionMetadata(sockCookie), nil
}

// LookupOrigDstV6 looks up original destination metadata for an IPv6 connection by socket cookie.
func (m *Maps) LookupOrigDstV6(sockCookie uint64) (*ConnectionMetadata, error) {
	key := connectOrigDstKeyV6{SockCookie: sockCookie}
	var val connectOrigDstValV6
	if err := m.OrigDstMapV6.Lookup(&key, &val); err != nil {
		return nil, err
	}
	return val.ToConnectionMetadata(sockCookie), nil
}

// LoadUserConfig loads the user configuration into the BPF maps.
// It sets the injection_time to the current boot time, which is used to
// reject processes that reuse a PID after monitoring started.
func (m *Maps) LoadUserConfig(config types.Config) error {
	// Set injection_time first - this must happen before adding PIDs
	// so that BPF can correctly validate processes
	injectionTime, err := GetBootTimeNs()
	if err != nil {
		return fmt.Errorf("get boot time: %w", err)
	}

	injectionKey := uint32(0)
	injectionVal := connectInjectionTimeVal{
		InjectionTime: injectionTime,
	}
	if err := m.InjectionTimeMap.Put(&injectionKey, &injectionVal); err != nil {
		return fmt.Errorf("set injection_time: %w", err)
	}

	// Add PIDs to allowlist (key is just PID now, no start_time)
	for _, pid := range config.ObservePIDs {
		key := connectPidAllowlistKey{
			Pid: pid,
		}
		val := connectPidAllowlistVal{
			NestedAllowed: 0,
		}
		if config.ObserveChildTree {
			val.NestedAllowed = 1
		}

		if err := m.PIDAllowlist.Put(&key, &val); err != nil {
			return fmt.Errorf("put pid %d in allowlist: %w", pid, err)
		}
	}

	for _, comm := range config.ObserveCommands {
		key := connectCommAllowlistKey{
			Comm: StringToCommInt8(comm),
		}
		val := uint8(1)

		if err := m.CommAllowlist.Put(&key, &val); err != nil {
			return fmt.Errorf("put comm %s in allowlist: %w", comm, err)
		}
	}

	for _, cgroupPath := range config.ObserveCgroups {
		cgroupID, err := GetCgroupID(cgroupPath)
		if err != nil {
			return fmt.Errorf("get cgroup id for %s: %w", cgroupPath, err)
		}

		key := connectCgroupAllowlistKey{
			CgroupId: cgroupID,
		}
		val := uint8(1)

		if err := m.CgroupAllowlist.Put(&key, &val); err != nil {
			return fmt.Errorf("put cgroup %s in allowlist: %w", cgroupPath, err)
		}
	}

	return nil
}

// GetCgroupID returns the cgroup ID for a given cgroup path.
// The cgroup ID is the inode number of the cgroup directory.
func GetCgroupID(cgroupPath string) (uint64, error) {
	var stat unix.Stat_t
	if err := unix.Stat(cgroupPath, &stat); err != nil {
		return 0, fmt.Errorf("stat cgroup %s: %w", cgroupPath, err)
	}
	return stat.Ino, nil
}

func GetSocketCookie(fd int) (uint64, error) {
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil {
		return 0, fmt.Errorf("getsockopt SO_COOKIE: %w", err)
	}
	return cookie, nil
}

// GetBootTimeNs returns the current time since boot in nanoseconds.
// This matches the kernel's CLOCK_BOOTTIME which is used by BPF's
// task->start_boottime field.
func GetBootTimeNs() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, fmt.Errorf("clock_gettime CLOCK_BOOTTIME: %w", err)
	}
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec), nil
}
