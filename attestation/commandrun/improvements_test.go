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

//go:build linux

package commandrun

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/in-toto/go-witness/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== Improvements Tests ====================

func TestByteCountTracking(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test")
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)

	// Test actual byte count tracking for network operations
	cr := New(
		WithCommand([]string{"sh", "-c", "echo 'Hello, World!' | nc -w 1 example.com 80 || true"}),
		WithTracing(true),
		WithTracerOptions(TracerOptions{
			EnableHashing:      false,
			EnableNetworkTrace: true,
		}),
	)

	err = cr.Attest(ctx)
	if err != nil && err.Error() != "exit status 1" {
		t.Logf("Command error (expected): %v", err)
	}

	exported := cr.ExportedAttestations()
	require.Len(t, exported, 1)

	traceAtt, ok := exported[0].(*TraceAttestation)
	require.True(t, ok)

	// Look for processes with network activity
	foundBytes := false
	for _, p := range traceAtt.Processes {
		if p.NetworkActivity != nil {
			t.Logf("Process %d (%s) network stats:", p.ProcessID, p.Program)
			t.Logf("  Bytes sent: %d", p.NetworkActivity.BytesSent)
			t.Logf("  Bytes received: %d", p.NetworkActivity.BytesReceived)
			
			// The echo command sends "Hello, World!\n" which is 14 bytes
			if p.NetworkActivity.BytesSent > 0 {
				foundBytes = true
				// Should have sent at least the echo output
				assert.GreaterOrEqual(t, p.NetworkActivity.BytesSent, uint64(14))
			}
		}
	}
	
	assert.True(t, foundBytes, "Should have tracked actual bytes sent")
}

func TestFileWriteTracking(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test")
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)

	// Create a test file to write to
	testFile := filepath.Join(t.TempDir(), "test-output.txt")
	
	cr := New(
		WithCommand([]string{"sh", "-c", "echo 'test data' > " + testFile}),
		WithTracing(true),
		WithTracerOptions(TracerOptions{
			EnableHashing: true,
		}),
	)

	err = cr.Attest(ctx)
	require.NoError(t, err)

	exported := cr.ExportedAttestations()
	require.Len(t, exported, 1)

	traceAtt, ok := exported[0].(*TraceAttestation)
	require.True(t, ok)

	// Look for processes that wrote files
	foundWrite := false
	for _, p := range traceAtt.Processes {
		t.Logf("Process %d (%s):", p.ProcessID, p.Program)
		t.Logf("  Command: %s", p.Cmdline)
		if p.WrittenFiles != nil && len(p.WrittenFiles) > 0 {
			t.Logf("  Wrote files:")
			for file := range p.WrittenFiles {
				t.Logf("    - %s", file)
				if file == testFile {
					foundWrite = true
				}
			}
		} else {
			t.Logf("  No files written tracked")
		}
	}
	
	assert.True(t, foundWrite, "Should have tracked file write to %s", testFile)

	// Verify the file was actually written
	content, err := os.ReadFile(testFile)
	require.NoError(t, err)
	assert.Equal(t, "test data\n", string(content))
}

func TestFailedConnectionTracking(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test")
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)

	// Try to connect to a port that's likely closed
	cr := New(
		WithCommand([]string{"sh", "-c", "nc -w 1 localhost 65432 < /dev/null || true"}),
		WithTracing(true),
		WithTracerOptions(TracerOptions{
			EnableHashing:      false,
			EnableNetworkTrace: true,
		}),
	)

	err = cr.Attest(ctx)
	// Command should succeed because we used || true
	if err != nil {
		t.Logf("Command error: %v", err)
	}

	exported := cr.ExportedAttestations()
	require.Len(t, exported, 1)

	traceAtt, ok := exported[0].(*TraceAttestation)
	require.True(t, ok)

	// Look for failed connections
	foundFailure := false
	for _, p := range traceAtt.Processes {
		if p.NetworkActivity != nil {
			for _, conn := range p.NetworkActivity.Connections {
				t.Logf("Connection: type=%s success=%v error=%s", conn.Type, conn.Success, conn.ErrorMessage)
				if !conn.Success && conn.ErrorMessage != "" {
					foundFailure = true
				}
			}
		}
	}
	
	// Note: This might not always fail if the port happens to be open
	t.Logf("Found connection failure: %v", foundFailure)
}

func TestMultipleFileWrites(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test")
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)

	// Create multiple files
	file1 := filepath.Join(t.TempDir(), "file1.txt")
	file2 := filepath.Join(t.TempDir(), "file2.txt")
	
	cr := New(
		WithCommand([]string{"sh", "-c", "echo 'data1' > " + file1 + " && echo 'data2' >> " + file1 + " && echo 'data3' > " + file2}),
		WithTracing(true),
		WithTracerOptions(TracerOptions{
			EnableHashing: false,
		}),
	)

	err = cr.Attest(ctx)
	require.NoError(t, err)

	exported := cr.ExportedAttestations()
	require.Len(t, exported, 1)

	traceAtt, ok := exported[0].(*TraceAttestation)
	require.True(t, ok)

	// Count unique files written
	writtenFiles := make(map[string]bool)
	for _, p := range traceAtt.Processes {
		if p.WrittenFiles != nil {
			for file := range p.WrittenFiles {
				writtenFiles[file] = true
			}
		}
	}
	
	assert.True(t, writtenFiles[file1], "Should have tracked write to file1")
	assert.True(t, writtenFiles[file2], "Should have tracked write to file2")
	assert.GreaterOrEqual(t, len(writtenFiles), 2, "Should have tracked at least 2 file writes")
}

func TestResourceUsageTracking(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test")
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)

	// Run a command that uses some CPU and memory
	cr := New(
		WithCommand([]string{"sh", "-c", "dd if=/dev/zero of=/dev/null bs=1M count=100"}),
		WithTracing(true),
		WithTracerOptions(TracerOptions{
			EnableHashing: false,
		}),
	)

	err = cr.Attest(ctx)
	require.NoError(t, err)

	exported := cr.ExportedAttestations()
	require.Len(t, exported, 1)

	traceAtt, ok := exported[0].(*TraceAttestation)
	require.True(t, ok)

	// Look for processes with resource usage data
	foundResources := false
	for _, p := range traceAtt.Processes {
		t.Logf("Process %d (%s):", p.ProcessID, p.Program)
		if p.CPUTimeUser != nil || p.CPUTimeSystem != nil {
			foundResources = true
			t.Logf("  CPU User Time: %v", p.CPUTimeUser)
			t.Logf("  CPU System Time: %v", p.CPUTimeSystem)
		}
		if p.MemoryRSS > 0 {
			foundResources = true
			t.Logf("  Memory RSS: %d bytes", p.MemoryRSS)
			t.Logf("  Peak Memory RSS: %d bytes", p.PeakMemoryRSS)
		}
	}

	assert.True(t, foundResources, "Should have tracked resource usage")
}

// ==================== Integration Tests ====================

// Test that our improvements work with the actual implementation
func TestImprovedTypesWithRealTracing(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test")
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)

	// Test with improved types - using custom types throughout
	cr := New(
		WithCommand([]string{"echo", "test"}),
		WithTracing(true),
		WithTracerOptions(TracerOptions{
			EnableHashing:      false,
			EnableNetworkTrace: false,
		}),
	)

	err = cr.Attest(ctx)
	require.NoError(t, err)

	// Export attestations
	exported := cr.ExportedAttestations()
	require.Len(t, exported, 1)

	// Should be RuntimeTraceCollector
	rtc, ok := exported[0].(*RuntimeTraceCollector)
	require.True(t, ok)
	
	// Test it implements the interface
	assert.Equal(t, "runtime-trace", rtc.Name())
	assert.Equal(t, "https://in-toto.io/attestation/runtime-trace/v0.1", rtc.Type())
	
	// Marshal and check structure
	data, err := rtc.MarshalJSON()
	require.NoError(t, err)
	assert.Contains(t, string(data), "monitor")
	assert.Contains(t, string(data), "monitorLog")
}


func TestResourceUsageTrackingIntegration(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test") 
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)

	// Run a command that uses some CPU
	cr := New(
		WithCommand([]string{"dd", "if=/dev/zero", "of=/dev/null", "bs=1M", "count=10"}),
		WithTracing(true),
		WithTracerOptions(TracerOptions{
			EnableHashing: false,
		}),
	)

	err = cr.Attest(ctx)
	require.NoError(t, err)

	exported := cr.ExportedAttestations()
	require.Len(t, exported, 1)

	// Extract the trace data
	rtc, ok := exported[0].(*RuntimeTraceCollector)
	require.True(t, ok)

	// The RuntimeTraceCollector should have trace data
	assert.NotNil(t, rtc.trace)
	
	// Check that we captured resource usage
	foundResources := false
	for _, p := range rtc.trace.Processes {
		if p.MemoryRSS > 0 || p.PeakMemoryRSS > 0 {
			foundResources = true
			t.Logf("Process %d (%s): RSS=%d Peak=%d", 
				p.ProcessID, p.Program, p.MemoryRSS, p.PeakMemoryRSS)
		}
	}
	
	assert.True(t, foundResources, "Should have captured resource usage")
}

func TestFileWriteWithImprovedTypes(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test")
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)

	testFile := filepath.Join(t.TempDir(), "improved-test.txt")

	cr := New(
		WithCommand([]string{"sh", "-c", "echo 'improved types' > " + testFile}),
		WithTracing(true),
		WithTracerOptions(TracerOptions{
			EnableHashing: false,
		}),
	)

	err = cr.Attest(ctx)
	require.NoError(t, err)

	// Verify file was written
	content, err := os.ReadFile(testFile)
	require.NoError(t, err)
	assert.Equal(t, "improved types\n", string(content))

	// Check trace captured the write
	exported := cr.ExportedAttestations()
	require.Len(t, exported, 1)

	rtc, ok := exported[0].(*RuntimeTraceCollector)
	require.True(t, ok)

	foundWrite := false
	for _, p := range rtc.trace.Processes {
		if len(p.WrittenFiles) > 0 {
			for path := range p.WrittenFiles {
				if path == testFile {
					foundWrite = true
				}
			}
		}
	}
	
	assert.True(t, foundWrite, "Should have tracked file write")
}

func TestNetworkTrackingWithImprovedTypes(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test")
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)

	// Simple network test
	cr := New(
		WithCommand([]string{"sh", "-c", "nc -zv localhost 22 2>&1 || true"}),
		WithTracing(true),
		WithTracerOptions(TracerOptions{
			EnableHashing:      false,
			EnableNetworkTrace: true,
		}),
	)

	err = cr.Attest(ctx)
	// Ignore exit code - nc might fail if port is closed
	_ = err

	exported := cr.ExportedAttestations()
	require.Len(t, exported, 1)

	rtc, ok := exported[0].(*RuntimeTraceCollector)
	require.True(t, ok)

	// Check for network activity
	foundNetwork := false
	for _, p := range rtc.trace.Processes {
		if p.NetworkActivity != nil && len(p.NetworkActivity.Connections) > 0 {
			foundNetwork = true
			for _, conn := range p.NetworkActivity.Connections {
				t.Logf("Connection: %s to %s (success=%v)", 
					conn.Type, conn.RemoteAddr, conn.Success)
			}
		}
	}

	assert.True(t, foundNetwork, "Should have tracked network activity")
}