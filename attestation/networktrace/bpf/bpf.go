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
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/in-toto/go-witness/attestation/networktrace/types"
	"golang.org/x/sys/unix"
)

const (
	BPFPinBasePath = "/sys/fs/bpf/witness-nettrace"

	PinPathOrigDstMap       = BPFPinBasePath + "/orig_dst_map"
	PinPathOrigDstMapV6     = BPFPinBasePath + "/orig_dst_map_v6"
	PinPathPIDAllowlist     = BPFPinBasePath + "/pid_allowlist"
	PinPathCommAllowlist    = BPFPinBasePath + "/comm_allowlist"
	PinPathCgroupAllowlist  = BPFPinBasePath + "/cgroup_allowlist"
	PinPathInjectionTimeMap = BPFPinBasePath + "/injection_time_map"
	PinPathTupleCookieMap   = BPFPinBasePath + "/tuple_to_cookie_map"
	PinPathTupleCookieMapV6 = BPFPinBasePath + "/tuple_to_cookie_map_v6"

	PinPathConnect4 = BPFPinBasePath + "/progs/connect4"
	PinPathConnect6 = BPFPinBasePath + "/progs/connect6"
	PinPathSockops  = BPFPinBasePath + "/progs/sockops"

	PinPathLinkConnect4 = BPFPinBasePath + "/links/connect4"
	PinPathLinkConnect6 = BPFPinBasePath + "/links/connect6"
	PinPathLinkSockops  = BPFPinBasePath + "/links/sockops"
)

type LoadConfig struct {
	CgroupPath string
	ProxyPort  uint16
	ProxyIPv4  string
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

func IsLoaded() bool {
	if _, err := os.Stat(PinPathConnect4); err == nil {
		return true
	}
	return false
}

// Load loads and attaches BPF programs using embedded bytecode from bpf2go.
func Load(cfg LoadConfig) error {
	if IsLoaded() {
		return nil
	}

	// Required to load bpf programs on some kernel versions
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	for _, dir := range []string{
		BPFPinBasePath,
		BPFPinBasePath + "/progs",
		BPFPinBasePath + "/links",
	} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create pin directory %s: %w", dir, err)
		}
	}

	hostNetnsInum, err := GetCurrentNetns()
	if err != nil {
		return fmt.Errorf("get current netns: %w", err)
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
		return fmt.Errorf("convert proxy IP: %w", err)
	}

	connectSpec, err := loadConnect()
	if err != nil {
		return fmt.Errorf("load connect spec: %w", err)
	}

	if err := connectSpec.Variables["proxy_port"].Set(uint32(proxyPort)); err != nil {
		return fmt.Errorf("set proxy_port in connect: %w", err)
	}
	if err := connectSpec.Variables["proxy_ip"].Set(proxyIPUint32); err != nil {
		return fmt.Errorf("set proxy_ip in connect: %w", err)
	}
	if err := connectSpec.Variables["host_netns_inum"].Set(hostNetnsInum); err != nil {
		return fmt.Errorf("set host_netns_inum in connect: %w", err)
	}

	connectOpts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: BPFPinBasePath,
		},
	}

	var connectObjs connectObjects
	if err := connectSpec.LoadAndAssign(&connectObjs, &connectOpts); err != nil {
		return fmt.Errorf("load connect objects: %w", err)
	}
	defer connectObjs.Close()

	sockopsSpec, err := loadSockops()
	if err != nil {
		return fmt.Errorf("load sockops spec: %w", err)
	}

	if err := sockopsSpec.Variables["host_netns_inum"].Set(hostNetnsInum); err != nil {
		return fmt.Errorf("set host_netns_inum in sockops: %w", err)
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
		return fmt.Errorf("load sockops objects: %w", err)
	}
	defer sockopsObjs.Close()

	type progAttachment struct {
		prog       *ebpf.Program
		pinPath    string
		linkPin    string
		attachType ebpf.AttachType
	}

	attachments := []progAttachment{
		{connectObjs.InterceptConnect4, PinPathConnect4, PinPathLinkConnect4, ebpf.AttachCGroupInet4Connect},
		{connectObjs.InterceptConnect6, PinPathConnect6, PinPathLinkConnect6, ebpf.AttachCGroupInet6Connect},
		{sockopsObjs.TcpSockops, PinPathSockops, PinPathLinkSockops, ebpf.AttachCGroupSockOps},
	}

	for _, att := range attachments {
		if att.prog == nil {
			return fmt.Errorf("program not found for %s", att.pinPath)
		}

		if err := att.prog.Pin(att.pinPath); err != nil {
			Unload(cfg)
			return fmt.Errorf("pin program %s: %w", att.pinPath, err)
		}

		// All cgroups in the subtree will also be traced
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cfg.CgroupPath,
			Attach:  att.attachType,
			Program: att.prog,
		})
		if err != nil {
			Unload(cfg)
			return fmt.Errorf("attach %s: %w", att.pinPath, err)
		}

		if err := l.Pin(att.linkPin); err != nil {
			l.Close()
			Unload(cfg)
			return fmt.Errorf("pin link %s: %w", att.linkPin, err)
		}
		l.Close()
	}

	return nil
}

// Unload detaches and removes all BPF programs and maps
func Unload(cfg LoadConfig) error {
	var errs []error

	linkPaths := []string{
		PinPathLinkConnect4,
		PinPathLinkConnect6,
		PinPathLinkSockops,
	}

	for _, linkPath := range linkPaths {
		if _, err := os.Stat(linkPath); err == nil {
			l, err := link.LoadPinnedLink(linkPath, nil)
			if err == nil {
				l.Close()
			}
			if err := os.Remove(linkPath); err != nil && !os.IsNotExist(err) {
				errs = append(errs, fmt.Errorf("remove link %s: %w", linkPath, err))
			}
		}
	}

	progPaths := []string{
		PinPathConnect4,
		PinPathConnect6,
		PinPathSockops,
	}

	for _, progPath := range progPaths {
		if err := os.Remove(progPath); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("remove program %s: %w", progPath, err))
		}
	}

	mapPaths := []string{
		PinPathOrigDstMap,
		PinPathOrigDstMapV6,
		PinPathPIDAllowlist,
		PinPathCommAllowlist,
		PinPathCgroupAllowlist,
		PinPathInjectionTimeMap,
		PinPathTupleCookieMap,
		PinPathTupleCookieMapV6,
	}

	for _, mapPath := range mapPaths {
		if err := os.Remove(mapPath); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("remove map %s: %w", mapPath, err))
		}
	}

	for _, dir := range []string{
		BPFPinBasePath + "/links",
		BPFPinBasePath + "/progs",
		BPFPinBasePath,
	} {
		if err := os.Remove(dir); err != nil && !os.IsNotExist(err) {
			// Directory might not be empty, that's okay
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors during unload: %v", errs)
	}

	return nil
}

func GetMaps() (*Maps, error) {
	if !IsLoaded() {
		return nil, errors.New("BPF programs not loaded")
	}

	maps := &Maps{}
	var err error

	maps.OrigDstMap, err = ebpf.LoadPinnedMap(PinPathOrigDstMap, nil)
	if err != nil {
		return nil, fmt.Errorf("load orig_dst_map: %w", err)
	}

	maps.OrigDstMapV6, err = ebpf.LoadPinnedMap(PinPathOrigDstMapV6, nil)
	if err != nil {
		maps.Close()
		return nil, fmt.Errorf("load orig_dst_map_v6: %w", err)
	}

	maps.PIDAllowlist, err = ebpf.LoadPinnedMap(PinPathPIDAllowlist, nil)
	if err != nil {
		maps.Close()
		return nil, fmt.Errorf("load pid_allowlist: %w", err)
	}

	maps.CommAllowlist, err = ebpf.LoadPinnedMap(PinPathCommAllowlist, nil)
	if err != nil {
		maps.Close()
		return nil, fmt.Errorf("load comm_allowlist: %w", err)
	}

	maps.CgroupAllowlist, err = ebpf.LoadPinnedMap(PinPathCgroupAllowlist, nil)
	if err != nil {
		maps.Close()
		return nil, fmt.Errorf("load cgroup_allowlist: %w", err)
	}

	maps.InjectionTimeMap, err = ebpf.LoadPinnedMap(PinPathInjectionTimeMap, nil)
	if err != nil {
		maps.Close()
		return nil, fmt.Errorf("load injection_time_map: %w", err)
	}

	maps.TupleCookieMap, err = ebpf.LoadPinnedMap(PinPathTupleCookieMap, nil)
	if err != nil {
		maps.Close()
		return nil, fmt.Errorf("load tuple_to_cookie_map: %w", err)
	}

	maps.TupleCookieMapV6, err = ebpf.LoadPinnedMap(PinPathTupleCookieMapV6, nil)
	if err != nil {
		maps.Close()
		return nil, fmt.Errorf("load tuple_to_cookie_map_v6: %w", err)
	}

	return maps, nil
}

// Maps holds references to BPF maps with typed accessor methods
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

func (m *Maps) LookupOrigDst(sockCookie uint64) (*connectOrigDstVal, error) {
	key := connectOrigDstKey{SockCookie: sockCookie}
	var val connectOrigDstVal
	if err := m.OrigDstMap.Lookup(&key, &val); err != nil {
		return nil, err
	}
	return &val, nil
}

func (m *Maps) LookupOrigDstV6(sockCookie uint64) (*connectOrigDstValV6, error) {
	key := connectOrigDstKeyV6{SockCookie: sockCookie}
	var val connectOrigDstValV6
	if err := m.OrigDstMapV6.Lookup(&key, &val); err != nil {
		return nil, err
	}
	return &val, nil
}

// Close closes all map handles
func (m *Maps) Close() error {
	var errs []error

	if m.OrigDstMap != nil {
		if err := m.OrigDstMap.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if m.OrigDstMapV6 != nil {
		if err := m.OrigDstMapV6.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if m.PIDAllowlist != nil {
		if err := m.PIDAllowlist.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if m.CommAllowlist != nil {
		if err := m.CommAllowlist.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if m.CgroupAllowlist != nil {
		if err := m.CgroupAllowlist.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if m.InjectionTimeMap != nil {
		if err := m.InjectionTimeMap.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if m.TupleCookieMap != nil {
		if err := m.TupleCookieMap.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if m.TupleCookieMapV6 != nil {
		if err := m.TupleCookieMapV6.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing maps: %v", errs)
	}
	return nil
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
