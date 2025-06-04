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
	"crypto"
	"encoding/json"
	"testing"
	"time"
	
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuntimeTraceConversion(t *testing.T) {
	// Create a sample trace attestation with all features
	now := time.Now()
	later := now.Add(2 * time.Second)
	cpuUser := 20 * time.Millisecond
	cpuSystem := 10 * time.Millisecond
	
	trace := &TraceAttestation{
		Processes: []ProcessInfo{
			{
				Program:   "/usr/bin/sh",
				ProcessID: 1234,
				ParentPID: 1000,
				Comm:      "sh",
				Cmdline:   "sh -c curl https://example.com > output.txt",
				StartTime: &now,
				EndTime:   &later,
				OpenedFiles: map[string]cryptoutil.DigestSet{
					"/etc/hosts": cryptoutil.DigestSet{
						cryptoutil.DigestValue{Hash: crypto.SHA256}: "abc123",
					},
				},
				WrittenFiles: map[string]cryptoutil.DigestSet{
					"output.txt": {},
				},
				NetworkActivity: &NetworkActivity{
					Sockets: []SocketInfo{
						{
							Domain:   "AF_INET",
							Type:     "SOCK_STREAM",
							Protocol: "tcp",
							Created:  &now,
						},
					},
					Connections: []ConnectionInfo{
						{
							Type:       "connect",
							Timestamp:  &now,
							RemoteAddr: "93.184.216.34:443",
							Success:    true,
						},
					},
					BytesSent:     234,
					BytesReceived: 1648,
				},
				CPUTimeUser:   &cpuUser,
				CPUTimeSystem: &cpuSystem,
				MemoryRSS:     8388608,
				PeakMemoryRSS: 10485760,
			},
		},
		EntryPoint: 1234,
		TracingOptions: TracerOptions{
			EnableHashing:      true,
			EnableNetworkTrace: true,
		},
		Platform:  "linux",
		StartTime: &now,
		EndTime:   &later,
	}
	
	// Convert to runtime trace
	rtc := NewRuntimeTraceCollector(trace)
	
	// Verify basic properties
	assert.Equal(t, "runtime-trace", rtc.Name())
	assert.Equal(t, "https://in-toto.io/attestation/runtime-trace/v0.1", rtc.Type())
	
	// Marshal to JSON and verify structure
	data, err := rtc.MarshalJSON()
	require.NoError(t, err)
	
	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)
	
	// Verify monitor section
	monitor := result["monitor"].(map[string]interface{})
	assert.Equal(t, "https://github.com/in-toto/go-witness/commandrun/v0.1.0", monitor["type"])
	
	// Verify monitorLog has all three sections
	monitorLog := result["monitorLog"].(map[string]interface{})
	assert.Contains(t, monitorLog, "process")
	assert.Contains(t, monitorLog, "network")
	assert.Contains(t, monitorLog, "fileAccess")
	
	// Verify process events
	processes := monitorLog["process"].([]interface{})
	assert.GreaterOrEqual(t, len(processes), 2) // At least start and exit events
	
	// Check start event
	startEvent := processes[0].(map[string]interface{})
	assert.Equal(t, "start", startEvent["eventType"])
	assert.Equal(t, "/usr/bin/sh", startEvent["processBinary"])
	assert.Equal(t, float64(1234), startEvent["processID"])
	
	// Find exit event with resource usage
	var foundResourceUsage bool
	for _, p := range processes {
		event := p.(map[string]interface{})
		if event["eventType"] == "exit" && event["resourceUsage"] != nil {
			foundResourceUsage = true
			usage := event["resourceUsage"].(map[string]interface{})
			assert.Equal(t, "20ms", usage["cpuTimeUser"])
			assert.Equal(t, "10ms", usage["cpuTimeSystem"])
			assert.Equal(t, float64(8388608), usage["memoryRSS"])
		}
	}
	assert.True(t, foundResourceUsage, "Should have found exit event with resource usage")
	
	// Verify network events
	networks := monitorLog["network"].([]interface{})
	assert.GreaterOrEqual(t, len(networks), 2) // Socket creation and connection
	
	// Verify file access
	fileAccess := monitorLog["fileAccess"].([]interface{})
	assert.GreaterOrEqual(t, len(fileAccess), 1)
	
	// Verify witness extensions
	extensions := result["x-witness"].(map[string]interface{})
	assert.Equal(t, "0.1.0", extensions["version"])
	
	// Check summary
	summary := extensions["summary"].(map[string]interface{})
	assert.Equal(t, float64(1), summary["totalProcesses"])
	assert.Equal(t, float64(234), summary["totalNetworkSent"])
	assert.Equal(t, float64(1648), summary["totalNetworkReceived"])
	
	// Check file writes are separated
	fileWrites := extensions["fileWrites"].([]interface{})
	assert.Equal(t, 1, len(fileWrites))
	writeEvent := fileWrites[0].(map[string]interface{})
	assert.Equal(t, "output.txt", writeEvent["path"])
}

func TestRuntimeTraceWithMultipleProcesses(t *testing.T) {
	// Test with a process tree
	now := time.Now()
	
	trace := &TraceAttestation{
		Processes: []ProcessInfo{
			{
				Program:   "/usr/bin/make",
				ProcessID: 1000,
				ParentPID: 999,
				StartTime: &now,
			},
			{
				Program:   "/usr/bin/gcc",
				ProcessID: 1001,
				ParentPID: 1000,
				StartTime: &now,
			},
			{
				Program:   "/usr/bin/ld",
				ProcessID: 1002,
				ParentPID: 1001,
				StartTime: &now,
			},
		},
		EntryPoint:     1000,
		TracingOptions: TracerOptions{},
		Platform:       "linux",
		StartTime:      &now,
		EndTime:        &now,
	}
	
	rtc := NewRuntimeTraceCollector(trace)
	data, err := rtc.MarshalJSON()
	require.NoError(t, err)
	
	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)
	
	// Check process tree in extensions
	extensions := result["x-witness"].(map[string]interface{})
	processTree := extensions["processTree"].(map[string]interface{})
	assert.Equal(t, float64(1000), processTree["entryPoint"])
	
	// Verify tree structure
	tree := processTree["tree"].(map[string]interface{})
	assert.Equal(t, float64(1000), tree["pid"])
	assert.Equal(t, "/usr/bin/make", tree["program"])
	
	// Check depth
	assert.Equal(t, float64(3), processTree["depth"])
}

func TestRuntimeTraceEmptyTrace(t *testing.T) {
	// Test with minimal data
	trace := &TraceAttestation{
		Processes:      []ProcessInfo{},
		EntryPoint:     0,
		TracingOptions: TracerOptions{},
		Platform:       "linux",
	}
	
	rtc := NewRuntimeTraceCollector(trace)
	data, err := rtc.MarshalJSON()
	require.NoError(t, err)
	
	// Should still produce valid runtime-trace format
	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)
	
	assert.Contains(t, result, "monitor")
	assert.Contains(t, result, "monitoredProcess")
	assert.Contains(t, result, "monitorLog")
}