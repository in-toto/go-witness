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
	"fmt"
	"strings"
	"time"

	"github.com/in-toto/go-witness/attestation"
	"github.com/invopop/jsonschema"
)

const (
	RuntimeTraceName = "runtime-trace"
	RuntimeTraceType = "https://in-toto.io/attestation/runtime-trace/v0.1"
	WitnessMonitorType = "https://github.com/in-toto/go-witness/commandrun/v0.1.0"
	WitnessVersion = "0.1.0"
)

func init() {
	attestation.RegisterAttestation(RuntimeTraceName, RuntimeTraceType, attestation.PostProductRunType, func() attestation.Attestor {
		return &RuntimeTraceCollector{}
	})
}

// RuntimeTraceCollector converts TraceAttestation to in-toto runtime-trace format
type RuntimeTraceCollector struct {
	trace *TraceAttestation
}

// NewRuntimeTraceCollector creates a new runtime trace collector from a trace attestation
func NewRuntimeTraceCollector(trace *TraceAttestation) *RuntimeTraceCollector {
	return &RuntimeTraceCollector{trace: trace}
}

func (rtc *RuntimeTraceCollector) Name() string {
	return RuntimeTraceName
}

func (rtc *RuntimeTraceCollector) Type() string {
	return RuntimeTraceType
}

func (rtc *RuntimeTraceCollector) RunType() attestation.RunType {
	return attestation.PostProductRunType
}

func (rtc *RuntimeTraceCollector) Schema() *jsonschema.Schema {
	// The runtime-trace schema is defined by in-toto specification
	return jsonschema.Reflect(rtc)
}

func (rtc *RuntimeTraceCollector) Attest(ctx *attestation.AttestationContext) error {
	// RuntimeTraceCollector is populated from TraceAttestation, not through Attest
	return nil
}

// MarshalJSON implements custom JSON marshaling to match the in-toto runtime-trace format
func (rtc *RuntimeTraceCollector) MarshalJSON() ([]byte, error) {
	if rtc.trace == nil {
		rtc.trace = &TraceAttestation{}
	}

	// Build the runtime-trace structure
	runtimeTrace := map[string]interface{}{
		"monitor": map[string]interface{}{
			"type": WitnessMonitorType,
		},
		"monitoredProcess": rtc.buildMonitoredProcess(),
		"monitorLog": map[string]interface{}{
			"process":    rtc.buildProcessEvents(),
			"network":    rtc.buildNetworkEvents(),
			"fileAccess": rtc.buildFileAccessEvents(),
		},
		"x-witness": rtc.buildWitnessExtensions(),
	}

	return json.Marshal(runtimeTrace)
}

func (rtc *RuntimeTraceCollector) buildMonitoredProcess() map[string]interface{} {
	if len(rtc.trace.Processes) == 0 {
		return map[string]interface{}{
			"pid":        0,
			"parentPID":  0,
			"cmd":        []string{},
			"startTime":  nil,
			"expiryTime": nil,
		}
	}

	// Find the entry point process
	var entryProcess *ProcessInfo
	for i := range rtc.trace.Processes {
		if rtc.trace.Processes[i].ProcessID == rtc.trace.EntryPoint {
			entryProcess = &rtc.trace.Processes[i]
			break
		}
	}

	if entryProcess == nil && len(rtc.trace.Processes) > 0 {
		entryProcess = &rtc.trace.Processes[0]
	}

	// Parse command line if available
	cmd := []string{}
	if entryProcess != nil {
		if entryProcess.Cmdline != "" {
			// Simple parsing - split by spaces (might need more sophisticated parsing for quoted args)
			cmd = strings.Fields(entryProcess.Cmdline)
		} else {
			cmd = []string{entryProcess.Program}
		}
	}

	result := map[string]interface{}{
		"pid":       rtc.trace.EntryPoint,
		"parentPID": 0,
		"cmd":       cmd,
	}

	if entryProcess != nil {
		result["parentPID"] = entryProcess.ParentPID
		if entryProcess.StartTime != nil {
			result["startTime"] = entryProcess.StartTime.Format(time.RFC3339Nano)
		}
		if entryProcess.EndTime != nil {
			result["expiryTime"] = entryProcess.EndTime.Format(time.RFC3339Nano)
		}
	}

	return result
}

func (rtc *RuntimeTraceCollector) buildProcessEvents() []interface{} {
	events := []interface{}{}

	for _, proc := range rtc.trace.Processes {
		// Process start event
		startEvent := map[string]interface{}{
			"eventType":     "start",
			"eventID":       fmt.Sprintf("process-start-%d", proc.ProcessID),
			"parentEventID": nil,
			"successful":    true,
			"processBinary": proc.Program,
			"processID":     proc.ProcessID,
			"parentPID":     proc.ParentPID,
		}

		if proc.StartTime != nil {
			startEvent["timestamp"] = proc.StartTime.Format(time.RFC3339Nano)
		}

		if proc.Cmdline != "" {
			startEvent["commandLine"] = proc.Cmdline
		}

		events = append(events, startEvent)

		// Process exit event with resource usage
		if proc.EndTime != nil {
			exitEvent := map[string]interface{}{
				"eventType":     "exit",
				"eventID":       fmt.Sprintf("process-exit-%d", proc.ProcessID),
				"parentEventID": fmt.Sprintf("process-start-%d", proc.ProcessID),
				"successful":    true,
				"processID":     proc.ProcessID,
				"timestamp":     proc.EndTime.Format(time.RFC3339Nano),
			}

			// Add resource usage if available
			resourceUsage := map[string]interface{}{}
			hasResourceUsage := false

			if proc.CPUTimeUser != nil {
				resourceUsage["cpuTimeUser"] = proc.CPUTimeUser.String()
				hasResourceUsage = true
			}
			if proc.CPUTimeSystem != nil {
				resourceUsage["cpuTimeSystem"] = proc.CPUTimeSystem.String()
				hasResourceUsage = true
			}
			if proc.MemoryRSS > 0 {
				resourceUsage["memoryRSS"] = proc.MemoryRSS
				hasResourceUsage = true
			}
			if proc.PeakMemoryRSS > 0 {
				resourceUsage["peakMemoryRSS"] = proc.PeakMemoryRSS
				hasResourceUsage = true
			}

			if hasResourceUsage {
				exitEvent["resourceUsage"] = resourceUsage
			}

			events = append(events, exitEvent)
		}
	}

	return events
}

func (rtc *RuntimeTraceCollector) buildNetworkEvents() []interface{} {
	events := []interface{}{}

	for _, proc := range rtc.trace.Processes {
		if proc.NetworkActivity == nil {
			continue
		}

		// Socket creation events
		for i, socket := range proc.NetworkActivity.Sockets {
			event := map[string]interface{}{
				"eventType":     "socket",
				"eventID":       fmt.Sprintf("socket-%d-%d", proc.ProcessID, i),
				"parentEventID": fmt.Sprintf("process-start-%d", proc.ProcessID),
				"successful":    true,
				"processID":     proc.ProcessID,
				"socketDomain":  socket.Domain,
				"socketType":    socket.Type,
				"protocol":      socket.Protocol,
			}

			if socket.Created != nil {
				event["timestamp"] = socket.Created.Format(time.RFC3339Nano)
			}

			events = append(events, event)
		}

		// Connection events
		for i, conn := range proc.NetworkActivity.Connections {
			event := map[string]interface{}{
				"eventType":     conn.Type,
				"eventID":       fmt.Sprintf("connection-%d-%d", proc.ProcessID, i),
				"parentEventID": fmt.Sprintf("process-start-%d", proc.ProcessID),
				"successful":    conn.Success,
				"processID":     proc.ProcessID,
			}

			if conn.LocalAddr != "" {
				event["localAddress"] = conn.LocalAddr
			}
			if conn.RemoteAddr != "" {
				event["remoteAddress"] = conn.RemoteAddr
			}
			if conn.Timestamp != nil {
				event["timestamp"] = conn.Timestamp.Format(time.RFC3339Nano)
			}
			if conn.ErrorMessage != "" {
				event["error"] = conn.ErrorMessage
			}

			events = append(events, event)
		}
	}

	return events
}

func (rtc *RuntimeTraceCollector) buildFileAccessEvents() []interface{} {
	events := []interface{}{}

	for _, proc := range rtc.trace.Processes {
		// File open events
		for path, digests := range proc.OpenedFiles {
			event := map[string]interface{}{
				"eventType":     "open",
				"eventID":       fmt.Sprintf("file-open-%d-%s", proc.ProcessID, path),
				"parentEventID": fmt.Sprintf("process-start-%d", proc.ProcessID),
				"successful":    true,
				"processID":     proc.ProcessID,
				"path":          path,
				"mode":          "read",
			}

			// Add digests if available
			if len(digests) > 0 {
				digestMap := map[string]string{}
				for alg, digest := range digests {
					digestMap[alg.String()] = digest
				}
				event["digests"] = digestMap
			}

			events = append(events, event)
		}
	}

	return events
}

func (rtc *RuntimeTraceCollector) buildWitnessExtensions() map[string]interface{} {
	extensions := map[string]interface{}{
		"version": WitnessVersion,
		"tracingOptions": map[string]interface{}{
			"enableHashing":      rtc.trace.TracingOptions.EnableHashing,
			"enableNetworkTrace": rtc.trace.TracingOptions.EnableNetworkTrace,
		},
		"platform": rtc.trace.Platform,
	}

	// Add summary statistics
	summary := map[string]interface{}{
		"totalProcesses": len(rtc.trace.Processes),
	}

	var totalBytesSent, totalBytesReceived uint64
	var totalFilesOpened, totalFilesWritten int

	for _, proc := range rtc.trace.Processes {
		if proc.NetworkActivity != nil {
			totalBytesSent += proc.NetworkActivity.BytesSent
			totalBytesReceived += proc.NetworkActivity.BytesReceived
		}
		totalFilesOpened += len(proc.OpenedFiles)
		totalFilesWritten += len(proc.WrittenFiles)
	}

	summary["totalNetworkSent"] = totalBytesSent
	summary["totalNetworkReceived"] = totalBytesReceived
	summary["totalFilesOpened"] = totalFilesOpened
	summary["totalFilesWritten"] = totalFilesWritten

	extensions["summary"] = summary

	// Add process tree structure
	if len(rtc.trace.Processes) > 0 {
		extensions["processTree"] = rtc.buildProcessTree()
	}

	// Add file writes separately (not part of standard file access)
	fileWrites := []interface{}{}
	for _, proc := range rtc.trace.Processes {
		for path, digests := range proc.WrittenFiles {
			write := map[string]interface{}{
				"processID": proc.ProcessID,
				"path":      path,
			}

			if len(digests) > 0 {
				digestMap := map[string]string{}
				for alg, digest := range digests {
					digestMap[alg.String()] = digest
				}
				write["digests"] = digestMap
			}

			fileWrites = append(fileWrites, write)
		}
	}

	if len(fileWrites) > 0 {
		extensions["fileWrites"] = fileWrites
	}

	return extensions
}

func (rtc *RuntimeTraceCollector) buildProcessTree() map[string]interface{} {
	// Build a map of PID to process for quick lookup
	pidMap := make(map[int]*ProcessInfo)
	for i := range rtc.trace.Processes {
		pidMap[rtc.trace.Processes[i].ProcessID] = &rtc.trace.Processes[i]
	}

	// Build the tree structure
	type processNode struct {
		PID      int                      `json:"pid"`
		Program  string                   `json:"program"`
		Children []*processNode           `json:"children,omitempty"`
	}

	// Find root processes and build tree
	roots := []*processNode{}
	nodeMap := make(map[int]*processNode)

	// Create nodes
	for _, proc := range rtc.trace.Processes {
		node := &processNode{
			PID:      proc.ProcessID,
			Program:  proc.Program,
			Children: []*processNode{},
		}
		nodeMap[proc.ProcessID] = node
	}

	// Build parent-child relationships
	for _, proc := range rtc.trace.Processes {
		if parent, exists := nodeMap[proc.ParentPID]; exists {
			parent.Children = append(parent.Children, nodeMap[proc.ProcessID])
		} else {
			// No parent in our trace, this is a root
			roots = append(roots, nodeMap[proc.ProcessID])
		}
	}

	// Find the entry point's tree
	var entryTree *processNode
	if entry, exists := nodeMap[rtc.trace.EntryPoint]; exists {
		// Walk up to find the root of this tree
		current := entry
		for {
			found := false
			for _, proc := range rtc.trace.Processes {
				if proc.ProcessID == current.PID {
					if parent, exists := nodeMap[proc.ParentPID]; exists {
						current = parent
						found = true
						break
					}
				}
			}
			if !found {
				entryTree = current
				break
			}
		}
	}

	// Calculate tree depth
	var calculateDepth func(*processNode) int
	calculateDepth = func(node *processNode) int {
		if len(node.Children) == 0 {
			return 1
		}
		maxChildDepth := 0
		for _, child := range node.Children {
			depth := calculateDepth(child)
			if depth > maxChildDepth {
				maxChildDepth = depth
			}
		}
		return maxChildDepth + 1
	}

	depth := 0
	if entryTree != nil {
		depth = calculateDepth(entryTree)
	}

	result := map[string]interface{}{
		"entryPoint": rtc.trace.EntryPoint,
		"roots":      roots,
		"depth":      depth,
	}

	if entryTree != nil {
		result["tree"] = entryTree
	}

	return result
}

// UnmarshalJSON implements custom JSON unmarshaling
func (rtc *RuntimeTraceCollector) UnmarshalJSON(data []byte) error {
	// For unmarshaling runtime-trace format back to TraceAttestation
	// This would be needed if we want to import runtime-trace format
	return fmt.Errorf("unmarshaling runtime-trace format is not implemented")
}