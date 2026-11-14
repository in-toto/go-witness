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

package commandrun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"golang.org/x/sys/unix"
)

const (
	commandRunTraceCgroupPath = "/sys/fs/cgroup/witness-tracing"
	commandRunDigestJobBuffer = 1 << 16
	commandRunDigestWorkers   = 4
	commandRunExitWaitTimeout = 5 * time.Second
)

type digestJob struct {
	pid  int
	key  string // OpenedFiles key (as stored in the attestation)
	path string
}

// rootID identifies a process's root directory: its mount and inode.
type rootID struct {
	mntID uint32
	ino   uint64
}

type ebpfTraceContext struct {
	hash        []cryptoutil.DigestValue
	processes   map[int]*ProcessInfo
	exited      map[int]struct{}
	exitNotify  chan struct{}
	digestJobs  chan digestJob
	digestWg    sync.WaitGroup
	mu          sync.Mutex
	cgroupPaths map[uint64]string
	// Open fds to every root seen in open events, so files can be hashed
	// under it after the processes using it have exited.
	rootFDs map[rootID]int
}

func (rc *CommandRun) usesEBPFTracing() bool {
	return rc.traceBackend == TraceBackendEBPF
}

// Common userspace harness for command-run eBPF tracing.
// - Create per-run cgroup.
// - Load selected BPF program, drain the ring-bugger that stores open/exec/exit events.
// - Process events to populate ProcessInfo and OpenedFiles.
func (rc *CommandRun) traceWithEBPF(c *exec.Cmd, actx *attestation.AttestationContext, hasPreExec bool) ([]ProcessInfo, error) {
	cgroupFile, cgroupID, cgroupPath, err := prepareCommandRunTraceCgroup()
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := os.Remove(cgroupPath); err != nil {
			log.Debugf("command-run: could not remove trace cgroup %s: %v", cgroupPath, err)
		}
	}()
	defer cgroupFile.Close()

	if c.SysProcAttr == nil {
		c.SysProcAttr = &unix.SysProcAttr{}
	}
	c.SysProcAttr.UseCgroupFD = true
	c.SysProcAttr.CgroupFD = int(cgroupFile.Fd())

	pctx := &ebpfTraceContext{
		hash:        actx.Hashes(),
		processes:   make(map[int]*ProcessInfo),
		exited:      make(map[int]struct{}),
		exitNotify:  make(chan struct{}, 1),
		cgroupPaths: map[uint64]string{},
		rootFDs:     map[rootID]int{},
	}
	defer pctx.closeRootFDs()

	// Load eBPF tracing programs.
	var loaded *loadedEBPFTracer
	switch rc.traceBackend {
	case TraceBackendEBPF:
		loaded, err = loadSyscallEBPFTracer(cgroupID, rc.trackCgroup, rc.daemonPIDs)
	default:
		return nil, fmt.Errorf("unknown EBPF backend: %s", rc.traceBackend)
	}
	if err != nil {
		return nil, fmt.Errorf("load command-run eBPF file tracer: %w", err)
	}
	defer func() { _ = loaded.close() }()

	// Populate information for daemon PIDs since we don't see an EVENT_TYPE_EXEC for these.
	for _, pid := range rc.daemonPIDs {
		statusBytes, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		cmdlineBytes, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		exePath, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))

		pctx.mu.Lock()
		procInfo := pctx.getProcInfo(pid, pid)
		if ppid, err := getPPIDFromStatus(statusBytes); err == nil {
			procInfo.ParentPID = ppid
		}
		for line := range strings.SplitSeq(string(statusBytes), "\n") {
			if comm, found := strings.CutPrefix(line, "Name:"); found {
				procInfo.Comm = strings.TrimSpace(comm)
				break
			}
		}
		procInfo.Cmdline = argvToCmdline(cmdlineBytes)
		procInfo.Program = exePath
		pctx.mu.Unlock()

		pctx.populateMetadataForProc(pid)
	}

	log.Infof("Using tracer: %s for command-run", rc.traceBackend)

	// Start the ring buffer reader before the command starts so short-lived
	// processes cannot fill the buffer before userspace begins draining it.
	reader, err := ringbuf.NewReader(loaded.events)
	if err != nil {
		return nil, fmt.Errorf("create command-run file trace reader: %w", err)
	}

	pctx.startDigestWorkers(commandRunDigestWorkers)

	var readErr error
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		if err := pctx.readEvents(reader); err != nil {
			// Record any errors in reading events here to avoid racing over c.Process
			// since this goroutine runs concurrently with c.Start()
			readErr = err
			log.Errorf("command-run eBPF trace error: %v", err)
		}
	}()

	// Shut down in order: stop the reader first, so nothing sends on
	// digestJobs after finishDigestWorkers closes it. Runs at most once.
	stop := sync.OnceFunc(func() {
		_ = reader.Close()
		<-readerDone
		pctx.finishDigestWorkers()
	})
	defer stop()

	var waitErr error
	if hasPreExec {
		waitErr = rc.runWithPreExec(c)
		if c.Process == nil {
			return nil, waitErr
		}
	} else {
		if err := c.Start(); err != nil {
			return nil, err
		}

		// Stop the command if tracing failed, instead of finishing with missing
		// events.
		go func() {
			<-readerDone
			if readErr != nil {
				_ = c.Process.Kill()
			}
		}()

		waitErr = c.Wait()
		rc.ExitCode = exitCodeFromErr(waitErr, c)
	}

	pctx.mu.Lock()
	pctx.getProcInfo(c.Process.Pid, c.Process.Pid)
	pctx.mu.Unlock()

	// Process completion does not mean userspace has drained every event already
	// queued in the ring buffer. Wait until the reader processes the main task's
	// sched_process_exit event
	exitSeen := pctx.waitForExit(c.Process.Pid, readerDone)

	stop()

	if readErr != nil {
		return pctx.procInfoArray(), readErr
	}

	// Fail if ringbuffer failed to reserve space for an event.
	if err := loaded.checkRingbufDrops(); err != nil {
		return pctx.procInfoArray(), err
	}

	if !exitSeen {
		return pctx.procInfoArray(), fmt.Errorf(
			"timed out waiting for command-run eBPF exit event for pid %d",
			c.Process.Pid,
		)
	}

	if waitErr != nil {
		return pctx.procInfoArray(), waitErr
	}

	return pctx.procInfoArray(), nil
}

// readEvents is deliberately thin because it is the ring-buffer drain loop. It
// decodes one event, performs the minimum ProcessInfo update, and queues slower
// work outside the lock so the kernel buffer is drained before it overruns.
func (p *ebpfTraceContext) readEvents(reader *ringbuf.Reader) error {
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return err
		}

		var event fileOpenEvent
		eventSize := binary.Size(event)
		if len(record.RawSample) != eventSize {
			return fmt.Errorf("read command-run eBPF event: expected %d bytes, got %d", eventSize, len(record.RawSample))
		}
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			return fmt.Errorf("decode command-run eBPF event: %w", err)
		}

		if event.EventType == eventTypeError {
			return formatEBPFTraceError(event)
		}

		if event.EventType == eventTypeCgroupMkdir {
			path := cleanCString(event.payload())
			p.mu.Lock()
			p.cgroupPaths[event.CgroupID] = path
			p.mu.Unlock()
			log.Debugf("command-run: tracking cgroup %d (%s), created by host pid %d", event.CgroupID, path, event.HostPID)
			continue
		}

		// Task is outside witness's PID namespace; /proc can't be used to resolve its files.
		if event.HostPID == 0 {
			continue
		}

		// Use Host coded PID/TIDs.
		var shouldEnrich bool
		pid := int(event.HostPID)

		var procInfo *ProcessInfo

		p.mu.Lock()

		switch event.EventType {
		case eventTypeOpen:
			procInfo = p.getProcInfo(pid, int(event.PID))
			procInfo.CgroupID = event.CgroupID

			if event.DataLen > 0 {
				key, hashPath := p.openEventPaths(pid, &event)
				if !skipDigestPath(key) {
					if _, exists := procInfo.OpenedFiles[key]; !exists {
						procInfo.OpenedFiles[key] = nil

						// Enqueue a digest job for the given (pid, key, path).
						// Digest calculation can block on disk I/O, so keep the ring-buffer
						// reader moving.
						select {
						case p.digestJobs <- digestJob{pid: pid, key: key, path: hashPath}:
						default:
						}
					}
				}
			}

		case eventTypeOpenRaw:
			// BPF couldn't resolve the fd, so this is the path as passed to
			// open. Recorded without a digest.
			procInfo = p.getProcInfo(pid, int(event.PID))
			procInfo.CgroupID = event.CgroupID
			key := cleanCString(event.payload())
			if key != "" && !skipDigestPath(key) {
				if _, exists := procInfo.OpenedFiles[key]; !exists {
					procInfo.OpenedFiles[key] = nil
				}
			}

		case eventTypeExec:
			procInfo = p.getProcInfo(pid, int(event.PID))
			procInfo.CgroupID = event.CgroupID
			program, argv, _ := bytes.Cut(event.payload(), []byte{0})
			// Fallback from the eBPF event. Might be overwritten by /proc data later.
			if len(program) > 0 {
				procInfo.Program = string(program)
				procInfo.Comm = filepath.Base(procInfo.Program)
			}
			procInfo.Cmdline = argvToCmdline(argv)
			shouldEnrich = true

		case eventTypeExit:
			procInfo = p.processes[pid]

		case eventTypeGroupExit:
			procInfo = p.processes[pid]

			// Mark a PID as exited and send an exitNotify.
			p.exited[pid] = struct{}{}

			select {
			case p.exitNotify <- struct{}{}:
			default:
			}
		}

		if procInfo != nil && procInfo.ParentPID == 0 {
			procInfo.ParentPID = int(event.HostPPID)
		}

		p.mu.Unlock()

		if shouldEnrich {
			p.populateMetadataForProc(pid)
		}
	}
}

// Waits until one of exitNotify, readerDone, or a 5-second timer are awake.
// Returns:
//
//	"true" for exitNotify, and non-erroring readerDone
//	"false" for timer
func (p *ebpfTraceContext) waitForExit(pid int, readerDone <-chan struct{}) bool {
	timer := time.NewTimer(commandRunExitWaitTimeout)
	defer timer.Stop()

	for {
		p.mu.Lock()
		_, exited := p.exited[pid]
		p.mu.Unlock()
		if exited {
			return true
		}

		select {
		case <-p.exitNotify:
		case <-readerDone:
			// The reader cannot observe another exit event after stopping.
			// Check once more in case it recorded this PID before exiting.
			p.mu.Lock()
			_, exited := p.exited[pid]
			p.mu.Unlock()
			return exited
		case <-timer.C:
			return false
		}
	}
}

// openEventPaths returns the OpenedFiles key and the path to hash for an open
// event. The key is the path BPF resolved, and it is hashed under the
// process's root via an fd held open since that root was first seen.
func (p *ebpfTraceContext) openEventPaths(pid int, event *fileOpenEvent) (key, hashPath string) {
	parts := strings.Split(strings.TrimRight(string(event.payload()), "\x00"), "\x00")
	slices.Reverse(parts)
	key = "/" + strings.Join(parts, "/")

	if fd, ok := p.rootFD(pid, rootID{event.RootMntID, event.RootIno}); ok {
		return key, fmt.Sprintf("/proc/self/fd/%d%s", fd, key)
	}
	return key, filepath.Join(fmt.Sprintf("/proc/%d/root", pid), key)
}

// rootFD returns an fd for the root identified by id, opening it from pid's
// /proc entry the first time that root is seen.
func (p *ebpfTraceContext) rootFD(pid int, id rootID) (int, bool) {
	if fd, ok := p.rootFDs[id]; ok {
		return fd, true
	}

	fd, err := unix.Open(fmt.Sprintf("/proc/%d/root", pid), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, false
	}
	// pid may have exited (and the pid been reused) or changed root since the
	// event, so only keep the fd if it is the root the event was resolved in.
	var stx unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_INO|unix.STATX_MNT_ID, &stx); err != nil ||
		stx.Mnt_id != uint64(id.mntID) || stx.Ino != id.ino {
		_ = unix.Close(fd)
		return 0, false
	}
	p.rootFDs[id] = fd
	return fd, true
}

func (p *ebpfTraceContext) closeRootFDs() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, fd := range p.rootFDs {
		_ = unix.Close(fd)
		delete(p.rootFDs, id)
	}
}

// Digest workers fill in OpenedFiles hashes asynchronously. If a temporary file
// disappears before it can be hashed, the file remains in the attestation with
// an empty digest instead of blocking or failing the event reader.
func (p *ebpfTraceContext) startDigestWorkers(count int) {
	p.digestJobs = make(chan digestJob, commandRunDigestJobBuffer)
	for range count {
		p.digestWg.Add(1)
		go func() {
			defer p.digestWg.Done()
			for job := range p.digestJobs {
				p.digestOne(job)
			}
		}()
	}
}

func (p *ebpfTraceContext) finishDigestWorkers() {
	close(p.digestJobs)
	p.digestWg.Wait()
}

func (p *ebpfTraceContext) digestOne(job digestJob) {
	digest, err := cryptoutil.CalculateDigestSetFromFile(job.path, p.hash)
	if errors.Is(err, fs.ErrNotExist) {
		// Opened by the process, but gone (or its /proc entry is) by now. Keep
		// it with an empty digest: the open itself is still evidence.
		log.Debugf("command-run: keeping file without digest, no longer reachable: %s", job.path)
		return
	}
	if err != nil {
		log.Debugf("command-run: marking unhashable file for removal: %s", job.path)
		// Not a regular file (e.g. FIFO, socket, directory).
		p.mu.Lock()
		if procInfo := p.processes[job.pid]; procInfo != nil {
			if procInfo.OpenedFiles[job.key] == nil {
				procInfo.OpenedFiles[job.key] = cryptoutil.DigestSet{}
			}
		}
		p.mu.Unlock()
		return
	}

	p.mu.Lock()
	if procInfo := p.processes[job.pid]; procInfo != nil {
		if procInfo.OpenedFiles[job.key] == nil {
			procInfo.OpenedFiles[job.key] = digest
		}
	}
	p.mu.Unlock()
}

// getProcInfo and the helpers below translate raw trace events into the
// command-run attestation schema. Generic BPF helpers are kept at the bottom of
// this file.
func (p *ebpfTraceContext) getProcInfo(hostKey, nsID int) *ProcessInfo {
	procInfo, ok := p.processes[hostKey]
	if !ok {
		procInfo = &ProcessInfo{
			ProcessID:     nsID,
			HostProcessID: hostKey,
			OpenedFiles:   make(map[string]cryptoutil.DigestSet),
		}
		p.processes[hostKey] = procInfo
	}

	return procInfo
}

// procInfoArray performs final schema normalization before returning the
// process list to the command-run attestor.
func (p *ebpfTraceContext) procInfoArray() []ProcessInfo {
	p.mu.Lock()
	defer p.mu.Unlock()

	processes := make([]ProcessInfo, 0, len(p.processes))
	for _, procInfo := range p.processes {
		// Prune files marked unhashable (empty digest)
		// Files that were hashable but gone before hashing are kept (nil digest)
		for key, digest := range procInfo.OpenedFiles {
			if digest != nil && len(digest) == 0 {
				delete(procInfo.OpenedFiles, key)
			}
		}

		if path := p.cgroupPaths[procInfo.CgroupID]; path != "" {
			procInfo.CgroupPath = path
		}
		processes = append(processes, *procInfo)
	}

	return processes
}

// Enrich ProcessInfo from /proc. These reads are best
// effort because exec/exit events can race with process teardown.
func (p *ebpfTraceContext) populateMetadataForProc(pid int) {
	cgroupBytes, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	cgroupPath := parseCgroupPath(cgroupBytes)

	var exeDigest cryptoutil.DigestSet
	// Hash through the magic link, not the readlink result: the link opens the
	// running binary even in another mount namespace. Fails once the process
	// has exited, which is acceptable.
	if digest, err := cryptoutil.CalculateDigestSetFromFile(fmt.Sprintf("/proc/%d/exe", pid), p.hash); err == nil {
		exeDigest = digest
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	procInfo, ok := p.processes[pid]
	if !ok {
		return
	}

	if procInfo.CgroupPath == "" && cgroupPath != "" {
		procInfo.CgroupPath = cgroupPath
	}
	if exeDigest != nil {
		procInfo.ExeDigest = exeDigest
	}
}
