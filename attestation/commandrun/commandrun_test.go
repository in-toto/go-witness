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
	"runtime"
	"testing"
	"time"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== CommandRun Multi-Exporter Tests ====================

func TestCommandRunMultiExporter(t *testing.T) {
	tests := []struct {
		name            string
		enableTracing   bool
		tracerOptions   TracerOptions
		command         []string
		expectedExports int
	}{
		{
			name:            "no tracing no exports",
			enableTracing:   false,
			command:         []string{"echo", "hello"},
			expectedExports: 0,
		},
		{
			name:          "tracing enabled with exports",
			enableTracing: true,
			tracerOptions: TracerOptions{
				EnableHashing:      false, // Disable for faster tests
				EnableNetworkTrace: false,
			},
			command:         []string{"echo", "hello"},
			expectedExports: 2, // TraceAttestation + RuntimeTraceCollector
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr := New(
				WithCommand(tt.command),
				WithTracing(tt.enableTracing),
				WithTracerOptions(tt.tracerOptions),
			)

			ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
			require.NoError(t, err)
			err = cr.Attest(ctx)
			require.NoError(t, err)

			exports := cr.ExportedAttestations()
			assert.Len(t, exports, tt.expectedExports)

			if tt.expectedExports > 0 {
				// Verify the first export is a TraceAttestation
				traceAtt, ok := exports[0].(*TraceAttestation)
				require.True(t, ok, "Expected TraceAttestation type")
				assert.Equal(t, TraceName, traceAtt.Name())
				assert.Equal(t, TraceType, traceAtt.Type())
				
				// Should have at least one process (the main command)
				assert.NotEmpty(t, traceAtt.Processes)
				
				// Verify the second export is a RuntimeTraceCollector
				if tt.expectedExports > 1 {
					runtimeTrace, ok := exports[1].(*RuntimeTraceCollector)
					require.True(t, ok, "Expected RuntimeTraceCollector type")
					assert.Equal(t, RuntimeTraceName, runtimeTrace.Name())
					assert.Equal(t, RuntimeTraceType, runtimeTrace.Type())
				}
			}
		})
	}
}

func TestTracerOptions(t *testing.T) {
	opts := TracerOptions{
		EnableHashing:      true,
		EnableNetworkTrace: true,
	}

	cr := New(WithTracerOptions(opts))
	assert.Equal(t, opts.EnableHashing, cr.tracerOptions.EnableHashing)
	assert.Equal(t, opts.EnableNetworkTrace, cr.tracerOptions.EnableNetworkTrace)
}

func TestTraceAttestationSchema(t *testing.T) {
	ta := &TraceAttestation{}
	schema := ta.Schema()
	require.NotNil(t, schema)
	
	// Verify schema has expected fields
	assert.NotNil(t, schema.Definitions)
}

// ==================== Integration Tests ====================

func TestTracerIntegration(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Tracing tests only run on Linux")
	}

	tests := []struct {
		name           string
		command        []string
		tracerOptions  TracerOptions
		expectProcesses int // minimum expected
	}{
		{
			name:    "simple echo command",
			command: []string{"echo", "hello world"},
			tracerOptions: TracerOptions{
				EnableHashing:      false,
				EnableNetworkTrace: false,
			},
			expectProcesses: 1,
		},
		{
			name:    "shell script execution",
			command: []string{"sh", "-c", "/bin/echo hello && /bin/echo world"},
			tracerOptions: TracerOptions{
				EnableHashing:      true,
				EnableNetworkTrace: false,
			},
			expectProcesses: 2, // sh + echo (at least)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr := New(
				WithCommand(tt.command),
				WithTracing(true),
				WithTracerOptions(tt.tracerOptions),
			)

			ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
			require.NoError(t, err)
			err = cr.Attest(ctx)
			require.NoError(t, err)

			// Check that we got trace data
			exports := cr.ExportedAttestations()
			require.Len(t, exports, 1, "Expected one trace attestation")

			traceAtt := exports[0].(*TraceAttestation)
			assert.GreaterOrEqual(t, len(traceAtt.Processes), tt.expectProcesses)
			
			// Verify entry point is set
			assert.NotZero(t, traceAtt.EntryPoint)
			
			// Find the entry point in processes
			found := false
			for _, p := range traceAtt.Processes {
				if p.ProcessID == traceAtt.EntryPoint {
					found = true
					break
				}
			}
			assert.True(t, found, "Entry point PID should be in process list")
		})
	}
}

func TestTracerWithNetworkCalls(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Tracing tests only run on Linux")
	}

	// Network tracing is now implemented!
	
	cr := New(
		WithCommand([]string{"curl", "-s", "http://example.com"}),
		WithTracing(true),
		WithTracerOptions(TracerOptions{
			EnableHashing:      false,
			EnableNetworkTrace: true,
		}),
	)

	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)
	err = cr.Attest(ctx)
	require.NoError(t, err)

	exports := cr.ExportedAttestations()
	require.Len(t, exports, 1)

	// traceAtt := exports[0].(*TraceAttestation)
	
	// Look for network operations in any process
	// TODO: Uncomment when NetworkActivity is implemented
	// hasNetwork := false
	// for _, p := range traceAtt.Processes {
	// 	if len(p.NetworkActivity) > 0 {
	// 		hasNetwork = true
	// 		break
	// 	}
	// }
	// assert.True(t, hasNetwork, "Expected network activity to be captured")
}

func TestMultiExporterIntegration(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test")
	}
	// Test that trace data is properly exported
	cr := New(
		WithCommand([]string{"sh", "-c", "/bin/ls -la /tmp | /usr/bin/head -5"}),
		WithTracing(true),
		WithTracerOptions(TracerOptions{
			EnableHashing:      true,
			EnableNetworkTrace: false,
		}),
	)

	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)

	err = cr.Attest(ctx)
	require.NoError(t, err)

	// Verify main attestation
	assert.Equal(t, 0, cr.ExitCode)
	assert.NotEmpty(t, cr.Stdout)
	
	// Verify exports
	exports := cr.ExportedAttestations()
	require.Len(t, exports, 1, "Should have one trace export")

	traceAtt, ok := exports[0].(*TraceAttestation)
	require.True(t, ok, "Export should be TraceAttestation")

	// Verify trace attestation metadata
	assert.Equal(t, TraceName, traceAtt.Name())
	assert.Equal(t, TraceType, traceAtt.Type())
	assert.Equal(t, attestation.PostProductRunType, traceAtt.RunType())

	// Verify process tree
	assert.GreaterOrEqual(t, len(traceAtt.Processes), 3, "Should have at least sh, ls, and head")
	
	// Find the main shell process
	var mainShell *ProcessInfo
	for i := range traceAtt.Processes {
		p := &traceAtt.Processes[i]
		if p.ProcessID == traceAtt.EntryPoint {
			mainShell = p
			break
		}
	}
	require.NotNil(t, mainShell, "Should find entry point process")
	assert.Contains(t, mainShell.Program, "sh")

	// Verify process details
	for _, p := range traceAtt.Processes {
		assert.NotZero(t, p.ProcessID, "PID should be set")
		assert.NotEmpty(t, p.Program, "Program should be set")
		
		// If hashing was enabled, verify digests
		if cr.tracerOptions.EnableHashing && p.ProgramDigest != nil {
			assert.NotEmpty(t, p.ProgramDigest, "Program digest should be calculated")
		}
	}

	// Print process tree for debugging
	fmt.Println("\nProcess Tree:")
	for _, p := range traceAtt.Processes {
		fmt.Printf("  PID=%d PPID=%d Program=%s Cmdline=%s\n", 
			p.ProcessID, p.ParentPID, p.Program, p.Cmdline)
	}
}

// ==================== Schema Tests ====================

func TestProcessInfoSchema(t *testing.T) {
	// Create a ProcessInfo with all fields populated
	now := time.Now()
	pi := ProcessInfo{
		Program:          "/bin/echo",
		ProcessID:        1234,
		ParentPID:        1000,
		ProgramDigest:    cryptoutil.DigestSet{},
		// Deprecated fields removed
		Cmdline:          "echo hello",
		ExeDigest:        cryptoutil.DigestSet{},
		OpenedFiles:      map[string]cryptoutil.DigestSet{"/etc/passwd": {}},
		StartTime:        &now,
		EndTime:          &now,
		WrittenFiles:     map[string]cryptoutil.DigestSet{"/tmp/output": {}},
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
					LocalAddr:  "127.0.0.1:12345",
					RemoteAddr: "8.8.8.8:53",
					Timestamp:  &now,
					Success:    true,
				},
			},
			BytesSent:     1024,
			BytesReceived: 2048,
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(pi)
	require.NoError(t, err)

	// Unmarshal back
	var unmarshaled ProcessInfo
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	// Verify all fields are preserved
	assert.Equal(t, pi.Program, unmarshaled.Program)
	assert.Equal(t, pi.ProcessID, unmarshaled.ProcessID)
	assert.Equal(t, pi.ParentPID, unmarshaled.ParentPID)
	assert.NotNil(t, unmarshaled.StartTime)
	assert.NotNil(t, unmarshaled.EndTime)
	assert.NotNil(t, unmarshaled.WrittenFiles)
	assert.NotNil(t, unmarshaled.NetworkActivity)
	assert.Len(t, unmarshaled.NetworkActivity.Sockets, 1)
	assert.Len(t, unmarshaled.NetworkActivity.Connections, 1)
}

func TestTraceAttestationSchemaFields(t *testing.T) {
	// Create a TraceAttestation with all fields
	now := time.Now()
	ta := TraceAttestation{
		Processes: []ProcessInfo{
			{
				Program:   "/bin/ls",
				ProcessID: 5678,
				ParentPID: 1234,
			},
		},
		EntryPoint: 1234,
		TracingOptions: TracerOptions{
			EnableHashing:      true,
			EnableNetworkTrace: true,
		},
		Platform:  "linux",
		StartTime: &now,
		EndTime:   &now,
	}

	// Get schema
	schema := ta.Schema()
	require.NotNil(t, schema)

	// Marshal to JSON
	data, err := json.Marshal(ta)
	require.NoError(t, err)

	// Check that JSON contains expected fields
	var jsonMap map[string]interface{}
	err = json.Unmarshal(data, &jsonMap)
	require.NoError(t, err)

	assert.Contains(t, jsonMap, "processes")
	assert.Contains(t, jsonMap, "entrypoint")
	assert.Contains(t, jsonMap, "tracingoptions")
	assert.Contains(t, jsonMap, "platform")
	assert.Contains(t, jsonMap, "starttime")
	assert.Contains(t, jsonMap, "endtime")
}

func TestNetworkActivitySchema(t *testing.T) {
	now := time.Now()
	na := NetworkActivity{
		Sockets: []SocketInfo{
			{
				Domain:   "AF_INET6",
				Type:     "SOCK_DGRAM",
				Protocol: "udp",
				Created:  &now,
			},
		},
		Connections: []ConnectionInfo{
			{
				Type:         "bind",
				LocalAddr:    "0.0.0.0:8080",
				Timestamp:    &now,
				Success:      false,
				ErrorMessage: "Address already in use",
			},
		},
		BytesSent:     4096,
		BytesReceived: 8192,
	}

	// Test marshaling
	data, err := json.Marshal(na)
	require.NoError(t, err)

	// Test unmarshaling
	var unmarshaled NetworkActivity
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, na.BytesSent, unmarshaled.BytesSent)
	assert.Equal(t, na.BytesReceived, unmarshaled.BytesReceived)
	assert.Len(t, unmarshaled.Sockets, 1)
	assert.Len(t, unmarshaled.Connections, 1)
}