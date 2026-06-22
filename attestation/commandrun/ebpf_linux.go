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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/uuid"
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
	path string
}

type fileOpenEvent struct {
	EventType uint32
	PID       uint32
	TID       uint32
	Dfd       int32
	Error     int64
	Path      [256]byte
}

// loadedEBPFTracer is the generic contract between a BPF backend and this
// runner: an events map to read and a close function for links/objects.
type loadedEBPFTracer struct {
	events        *ebpf.Map
	targetCgroups *ebpf.Map
	close         func() error
}

func (t *loadedEBPFTracer) addCgroup(cgroupID uint64) error {
	if t.targetCgroups == nil {
		return fmt.Errorf("target cgroups map is not loaded")
	}
	var enabled uint8 = 1
	return t.targetCgroups.Put(cgroupID, enabled)
}

const (
	eventTypeOpen  = 1
	eventTypeExec  = 2
	eventTypeExit  = 3
	eventTypeError = 4
)

const (
	errorTypePendingOpenUpdate  = 1
	errorTypePendingOpenMissing = 2
)

type ebpfTraceContext struct {
	hash       []cryptoutil.DigestValue
	processes  map[int]*ProcessInfo
	exited     map[int]struct{}
	exitNotify chan struct{}
	digestJobs chan digestJob
	digestWg   sync.WaitGroup
	mu         sync.Mutex
}

func (rc *CommandRun) usesEBPFTracing() bool {
	return rc.traceBackend == TraceBackendEBPF
}

// Common userspace harness for command-run eBPF tracing.
// - Create per-run cgroup.
// - Load selected BPF program, drain the ring-bugger that stores open/exec/exit events.
// - Process events to populate ProcessInfo and OpenedFiles.
func (rc *CommandRun) traceWithEBPF(c *exec.Cmd, actx *attestation.AttestationContext, hasPreExec, hasPreExit bool) ([]ProcessInfo, error) {
	cgroupFile, cgroupID, err := prepareCommandRunTraceCgroup()
	if err != nil {
		return nil, err
	}
	defer cgroupFile.Close()

	if c.SysProcAttr == nil {
		c.SysProcAttr = &unix.SysProcAttr{}
	}
	c.SysProcAttr.UseCgroupFD = true
	c.SysProcAttr.CgroupFD = int(cgroupFile.Fd())

	pctx := &ebpfTraceContext{
		hash:       actx.Hashes(),
		processes:  make(map[int]*ProcessInfo),
		exited:     make(map[int]struct{}),
		exitNotify: make(chan struct{}, 1),
	}

	// Load eBPF tracing programs.
	var loaded *loadedEBPFTracer
	switch rc.traceBackend {
	case TraceBackendEBPF:
		loaded, err = loadSyscallEBPFTracer(cgroupID)
	default:
		return nil, fmt.Errorf("Unknown EBPF backend: %s", rc.traceBackend)
	}
	if err != nil {
		return nil, fmt.Errorf("load command-run eBPF file tracer: %w", err)
	}
	defer loaded.close()

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
	var readerWg sync.WaitGroup
	readerWg.Add(1)
	go func() {
		defer readerWg.Done()
		defer close(readerDone)
		if err := pctx.readEvents(reader); err != nil {
			// Internal tracing errors mean the attestation may be incomplete.
			// Stop the command and propagate the error instead of finishing with missing events.
			readErr = err
			log.Errorf("command-run eBPF trace error: %v", err)
			if c.Process != nil {
				_ = c.Process.Kill()
			}
		}
	}()

	if err := c.Start(); err != nil {
		reader.Close()
		readerWg.Wait()
		pctx.finishDigestWorkers()
		return nil, err
	}

	pctx.mu.Lock()
	pctx.getProcInfo(c.Process.Pid)
	pctx.mu.Unlock()

	var waitErr error
	if hasPreExec || hasPreExit {
		waitErr = rc.runWithHooks(c, hasPreExec, hasPreExit)
	} else {
		waitErr = c.Wait()
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			rc.ExitCode = exitErr.ExitCode()
		}
		if waitErr == nil && c.ProcessState != nil {
			rc.ExitCode = c.ProcessState.ExitCode()
		}
	}

	// Process completion does not mean userspace has drained every event already
	// queued in the ring buffer. Wait until the reader processes the main task's
	// sched_process_exit event; earlier open events precede it in the buffer.
	exitSeen := pctx.waitForExit(c.Process.Pid, readerDone)

	_ = reader.Close()
	readerWg.Wait()
	pctx.finishDigestWorkers()

	if readErr != nil {
		return pctx.procInfoArray(), readErr
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

		var shouldEnrich bool
		var exitedPID int
		pid := int(event.PID)
		var digestPath string

		var procInfo *ProcessInfo

		p.mu.Lock()

		switch event.EventType {
		case eventTypeOpen:
			pid = int(event.TID)
			procInfo = p.getProcInfo(pid)

			path := cleanCString(event.Path[:])

			if path != "" {
				openPath := resolveOpenPath(int(event.PID), int(event.Dfd), path)
				if _, exists := procInfo.OpenedFiles[openPath]; !exists {
					procInfo.OpenedFiles[openPath] = nil
					digestPath = openPath
				}
			}

		case eventTypeExec:
			procInfo = p.getProcInfo(pid)
			// Fallback from the eBPF event. Might be overwritten by /proc data later.
			if program := cleanCString(event.Path[:]); program != "" {
				procInfo.Program = program
				procInfo.Comm = filepath.Base(program)
			}
			shouldEnrich = true
		case eventTypeExit:
			procInfo = p.processes[pid]
			if procInfo != nil {
				shouldEnrich = true
			}
			exitedPID = pid
		}

		p.mu.Unlock()

		if digestPath != "" {
			// Digest calculation can block on disk I/O. Queue it after the
			// event update so the ring-buffer reader keeps moving.
			p.enqueueDigestJob(digestJob{pid: pid, path: digestPath})
		}

		if shouldEnrich {
			// /proc enrichment is attestation-schema work, not BPF plumbing.
			// Keep it out of the locked event update path.
			p.populateMetadataForProc(pid, event.EventType == eventTypeExec)
		}

		if exitedPID != 0 {
			p.mu.Lock()
			p.exited[exitedPID] = struct{}{}
			p.mu.Unlock()

			// One notification is enough to wake the waiter, which rechecks the set.
			select {
			case p.exitNotify <- struct{}{}:
			default:
			}
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

func cleanCString(data []byte) string {
	data = bytes.TrimLeft(data, "\x00")
	if i := bytes.IndexByte(data, 0); i >= 0 {
		data = data[:i]
	}
	return strings.TrimSpace(string(data))
}

func resolveOpenPath(pid, dfd int, path string) string {
	if filepath.IsAbs(path) {
		return path
	}

	procPath := fmt.Sprintf("/proc/%d/fd/%d", pid, dfd)
	if dfd == unix.AT_FDCWD {
		procPath = fmt.Sprintf("/proc/%d/cwd", pid)
	}

	if base, err := os.Readlink(procPath); err == nil {
		return filepath.Join(base, path)
	}

	return path
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

// Digest workers fill in OpenedFiles hashes asynchronously. If a temporary file
// disappears before it can be hashed, the file remains in the attestation with
// an empty digest instead of blocking or failing the event reader.
func (p *ebpfTraceContext) startDigestWorkers(count int) {
	p.digestJobs = make(chan digestJob, commandRunDigestJobBuffer)
	for range count {
		p.digestWg.Add(1)
		go p.digestWorker()
	}
}

func (p *ebpfTraceContext) finishDigestWorkers() {
	close(p.digestJobs)
	p.digestWg.Wait()
}

// enqueueDigestJob is non-blocking by design. Dropping a digest job is less bad
// than stalling the ring-buffer reader and losing later file events.
func (p *ebpfTraceContext) enqueueDigestJob(job digestJob) {
	select {
	case p.digestJobs <- job:
	default:
	}
}

func (p *ebpfTraceContext) digestWorker() {
	defer p.digestWg.Done()
	for job := range p.digestJobs {
		digest, err := cryptoutil.CalculateDigestSetFromFile(job.path, p.hash)
		if err != nil {
			continue
		}

		p.mu.Lock()
		if procInfo := p.processes[job.pid]; procInfo != nil {
			if procInfo.OpenedFiles[job.path] == nil {
				procInfo.OpenedFiles[job.path] = digest
			}
		}
		p.mu.Unlock()
	}
}

// getProcInfo and the helpers below translate raw trace events into the
// command-run attestation schema. Generic BPF helpers are kept at the bottom of
// this file.
func (p *ebpfTraceContext) getProcInfo(pid int) *ProcessInfo {
	procInfo, ok := p.processes[pid]
	if !ok {
		procInfo = &ProcessInfo{
			ProcessID:   pid,
			OpenedFiles: make(map[string]cryptoutil.DigestSet),
		}
		p.processes[pid] = procInfo
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
		// Drop obvious helper/kernel-worker style tasks that ptrace flow
		// typically does not materialize as command-run processes.
		if strings.HasPrefix(procInfo.Comm, "iou-sqp-") {
			continue
		}
		// Filter rows produced by transient/bad metadata states.
		if procInfo.Program != "" && !strings.HasPrefix(procInfo.Program, "/") {
			if procInfo.Comm == "" && procInfo.Cmdline == "" && len(procInfo.OpenedFiles) == 0 {
				continue
			}
		}
		// Minimal normalization: if program is missing but comm has a simple
		// executable-like token, promote comm to program for ptrace-like output.
		if procInfo.Program == "" && procInfo.Comm != "" && !strings.Contains(procInfo.Comm, " ") {
			procInfo.Program = procInfo.Comm
		}
		processes = append(processes, *procInfo)
	}

	return processes
}

// Enrich ProcessInfo from /proc. These reads are best
// effort because exec/exit events can race with process teardown.
func (p *ebpfTraceContext) populateMetadataForProc(pid int, overwrite bool) {
	statusBytes, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	cmdlineBytes, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	exePath, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))

	var ppid int
	if len(statusBytes) > 0 {
		if parsedPPID, err := getPPIDFromStatus(statusBytes); err == nil {
			ppid = parsedPPID
		}
	}
	comm := ""
	if len(statusBytes) > 0 {
		for line := range strings.SplitSeq(string(statusBytes), "\n") {
			if command, found := strings.CutPrefix(line, "Name:"); found {
				comm = strings.TrimSpace(command)
				break
			}
		}
	}
	cmdline := ""
	if len(cmdlineBytes) > 0 {
		parts := strings.Split(strings.TrimRight(string(cmdlineBytes), "\x00"), "\x00")
		if len(parts) > 0 && parts[0] != "" {
			cmdline = strings.Join(parts, " ")
		}
	}
	var exeDigest cryptoutil.DigestSet
	if exePath != "" {
		if digest, err := cryptoutil.CalculateDigestSetFromFile(exePath, p.hash); err == nil {
			exeDigest = digest
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	procInfo, ok := p.processes[pid]
	if !ok {
		return
	}
	if procInfo.ParentPID == 0 && ppid > 0 {
		procInfo.ParentPID = ppid
	}
	if (overwrite || procInfo.Comm == "") && comm != "" {
		procInfo.Comm = comm
	}
	if (overwrite || procInfo.Cmdline == "") && cmdline != "" {
		procInfo.Cmdline = cmdline
	}
	if (overwrite || procInfo.Program == "") && exePath != "" {
		procInfo.Program = exePath
	}
	if (overwrite || procInfo.ExeDigest == nil) && exeDigest != nil {
		procInfo.ExeDigest = exeDigest
	}
}

// Generic eBPF plumbing. cgroup id is used to filter for commands being traced.
func prepareCommandRunTraceCgroup() (*os.File, uint64, error) {
	// Create a randomly generated cgroup path to support parallel witness runs
	cgroupPath := fmt.Sprintf("%s-%s", commandRunTraceCgroupPath, uuid.NewString())

	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		return nil, 0, fmt.Errorf("create command-run trace cgroup: %w", err)
	}

	file, err := os.Open(cgroupPath)
	if err != nil {
		return nil, 0, fmt.Errorf("open command-run trace cgroup: %w", err)
	}

	var stat unix.Stat_t
	if err := unix.Stat(cgroupPath, &stat); err != nil {
		file.Close()
		return nil, 0, fmt.Errorf("stat command-run trace cgroup: %w", err)
	}

	return file, stat.Ino, nil
}

func closeLinks(links []link.Link) {
	for _, l := range links {
		if l != nil {
			_ = l.Close()
		}
	}
}
