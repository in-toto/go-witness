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

package commandrun

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

type fileOpenEvent struct {
	EventType uint32
	PID       uint32
	TID       uint32
	HostPID   uint32
	HostTID   uint32
	HostPPID  uint32
	CgroupID  uint64
	DataLen   uint32
	RootMntID uint32
	RootIno   uint64
	Error     int64
	Data      [4096]byte
}

const (
	eventTypeOpen        = 1
	eventTypeExec        = 2
	eventTypeExit        = 3
	eventTypeError       = 4
	eventTypeCgroupMkdir = 5
	eventTypeGroupExit   = 6
	eventTypeOpenRaw     = 7
)

const (
	errorTypePendingOpenUpdate  = 1
	errorTypePendingOpenMissing = 2
)

// loadedEBPFTracer is the generic contract between a BPF backend and this
// runner: an events map to read and a close function for links/objects.
type loadedEBPFTracer struct {
	events        *ebpf.Map
	targetCgroups *ebpf.Map
	daemonTasks   *ebpf.Map
	ringbufDrops  *ebpf.Map
	close         func() error
}

func (t *loadedEBPFTracer) addCgroup(cgroupID uint64) error {
	if t.targetCgroups == nil {
		return fmt.Errorf("target cgroups map is not loaded")
	}
	var enabled uint8 = 1
	return t.targetCgroups.Put(cgroupID, enabled)
}

// addDaemonPID seeds the in-kernel daemon-descendant allowlist with a root
// PID to follow.
func (t *loadedEBPFTracer) addDaemonPID(pid int) error {
	if t.daemonTasks == nil {
		return fmt.Errorf("daemon tasks map is not loaded")
	}
	if pid <= 0 {
		return fmt.Errorf("invalid daemon pid: %d", pid)
	}
	var enabled uint8 = 1
	return t.daemonTasks.Put(uint32(pid), enabled)
}

// payload returns Data[:DataLen], a NUL-separated list: path components leaf
// first (open), filename then argv (exec), or the cgroup path (cgroup mkdir).
// Bytes past DataLen are stale.
func (e *fileOpenEvent) payload() []byte {
	return e.Data[:min(int(e.DataLen), len(e.Data))]
}

func cleanCString(data []byte) string {
	if i := bytes.IndexByte(data, 0); i >= 0 {
		data = data[:i]
	}
	return strings.TrimSpace(string(data))
}

// argvToCmdline joins a NULL-separated argv with spaces.
func argvToCmdline(argv []byte) string {
	parts := strings.Split(strings.TrimRight(string(argv), "\x00"), "\x00")
	if parts[0] == "" {
		return ""
	}
	return strings.Join(parts, " ")
}

// parseCgroupPath extracts the cgroup v2 path from /proc/<pid>/cgroup
// Fallback for processes in pre-existing cgroups.
func parseCgroupPath(data []byte) string {
	for line := range strings.SplitSeq(string(data), "\n") {
		if rest, found := strings.CutPrefix(line, "0::"); found {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// Superseded: BPF now resolves every open's path itself, and drops opens it
// can't resolve.
// // resolveOpenPath returns the OpenedFiles key and the path to hash for a file
// // opened by pid. The key is the path as the process sees it. The file is read
// // through /proc/<pid>/... so it resolves against the process's own root and
// // cwd, which differ from witness's for containers.
// func resolveOpenPath(pid, dfd int, path string) (key, hashPath string) {
// 	if filepath.IsAbs(path) {
// 		return path, filepath.Join(fmt.Sprintf("/proc/%d/root", pid), path)
// 	}
//
// 	anchor := fmt.Sprintf("/proc/%d/cwd", pid)
// 	if dfd != unix.AT_FDCWD {
// 		anchor = fmt.Sprintf("/proc/%d/fd/%d", pid, dfd)
// 	}
// 	hashPath = filepath.Join(anchor, path)
// 	if base, err := os.Readlink(anchor); err == nil {
// 		return filepath.Join(base, path), hashPath
// 	}
// 	return path, hashPath
// }

// skipDigestPath reports whether an opened file, by its key (the path as the
// process saw it), should be left out. /proc, /sys and /dev are not hashable
// and not build evidence.
func skipDigestPath(key string) bool {
	top, _, _ := strings.Cut(strings.TrimPrefix(key, "/"), "/")
	return top == "proc" || top == "sys" || top == "dev"
}

// checkRingbufDrops fails the trace if any event was lost to a full ring
// buffer, since the attestation would be incomplete.
func (t *loadedEBPFTracer) checkRingbufDrops() error {
	var drops uint64
	if err := t.ringbufDrops.Lookup(uint32(0), &drops); err != nil {
		return fmt.Errorf("read command-run eBPF ring buffer drops: %w", err)
	}
	if drops > 0 {
		return fmt.Errorf("command-run eBPF trace dropped %d events: ring buffer full", drops)
	}
	return nil
}

func formatEBPFTraceError(event fileOpenEvent) error {
	switch event.Error {
	case errorTypePendingOpenUpdate:
		return fmt.Errorf("command-run eBPF trace failed to store pending open for pid %d tid %d", event.PID, event.TID)
	case errorTypePendingOpenMissing:
		return fmt.Errorf("command-run eBPF trace missing pending open for pid %d tid %d", event.PID, event.TID)
	default:
		return fmt.Errorf("command-run eBPF trace failed to capture opened filename for pid %d tid %d: %d", event.PID, event.TID, event.Error)
	}
}

// Generic eBPF plumbing. cgroup id is used to filter for commands being traced.
// The caller removes the returned path once the traced command has exited.
func prepareCommandRunTraceCgroup() (*os.File, uint64, string, error) {
	// Create a randomly generated cgroup path to support parallel witness runs
	cgroupPath := fmt.Sprintf("%s-%s", commandRunTraceCgroupPath, uuid.NewString())

	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		return nil, 0, "", fmt.Errorf("create command-run trace cgroup: %w", err)
	}

	file, err := os.Open(cgroupPath)
	if err != nil {
		_ = os.Remove(cgroupPath)
		return nil, 0, "", fmt.Errorf("open command-run trace cgroup: %w", err)
	}

	var stat unix.Stat_t
	if err := unix.Stat(cgroupPath, &stat); err != nil {
		file.Close()
		_ = os.Remove(cgroupPath)
		return nil, 0, "", fmt.Errorf("stat command-run trace cgroup: %w", err)
	}

	return file, stat.Ino, cgroupPath, nil
}

func closeLinks(links []link.Link) {
	for _, l := range links {
		if l != nil {
			_ = l.Close()
		}
	}
}
