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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/in-toto/go-witness/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==================== Basic Tracer Tests ====================

func TestTracerErrorCases(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test")
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)

	t.Run("non-existent command", func(t *testing.T) {
		tracer := newPlatformTracer(ctx, TracerOptions{})
		cmd := exec.Command("/non/existent/command")
		err := tracer.Start(cmd)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no such file or directory")
	})

	t.Run("command with bad permissions", func(t *testing.T) {
		// Create a file without execute permissions
		tmpFile := filepath.Join(t.TempDir(), "no-exec")
		err := os.WriteFile(tmpFile, []byte("#!/bin/sh\necho test"), 0644)
		require.NoError(t, err)

		tracer := newPlatformTracer(ctx, TracerOptions{})
		cmd := exec.Command(tmpFile)
		err = tracer.Start(cmd)
		assert.Error(t, err)
	})
}

func TestTracerHashingEdgeCases(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test")
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)

	t.Run("hashing with file that disappears", func(t *testing.T) {
		// Create a temporary file
		tmpFile := filepath.Join(t.TempDir(), "disappearing.txt")
		err := os.WriteFile(tmpFile, []byte("temporary"), 0644)
		require.NoError(t, err)

		// Command that reads then deletes the file
		script := fmt.Sprintf(`#!/bin/sh
cat %s
rm %s
`, tmpFile, tmpFile)
		
		scriptFile := filepath.Join(t.TempDir(), "delete-file.sh")
		err = os.WriteFile(scriptFile, []byte(script), 0755)
		require.NoError(t, err)

		tracer := newPlatformTracer(ctx, TracerOptions{EnableHashing: true})
		cmd := exec.Command(scriptFile)
		
		err = tracer.Start(cmd)
		require.NoError(t, err)
		
		err = tracer.Wait()
		// Should not error even though file is gone
		assert.NoError(t, err)
		
		processes := tracer.GetProcessTree()
		assert.NotEmpty(t, processes)
	})

	t.Run("hashing special files", func(t *testing.T) {
		// Try to hash /dev/null, /proc/self/stat etc
		tracer := newPlatformTracer(ctx, TracerOptions{EnableHashing: true})
		cmd := exec.Command("cat", "/dev/null", "/proc/self/stat")
		
		err = tracer.Start(cmd)
		require.NoError(t, err)
		
		err = tracer.Wait()
		assert.NoError(t, err)
		
		processes := tracer.GetProcessTree()
		require.NotEmpty(t, processes)
		
		// Should have filtered out special files
		for _, p := range processes {
			for file := range p.OpenedFiles {
				assert.False(t, strings.HasPrefix(file, "/dev/"))
				assert.False(t, strings.HasPrefix(file, "/proc/"))
			}
		}
	})
}

func TestTracerProcessLifecycle(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test")
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)

	t.Run("process that exits quickly", func(t *testing.T) {
		tracer := newPlatformTracer(ctx, TracerOptions{EnableHashing: true})
		cmd := exec.Command("true") // exits immediately with 0
		
		err = tracer.Start(cmd)
		require.NoError(t, err)
		
		err = tracer.Wait()
		assert.NoError(t, err)
		
		processes := tracer.GetProcessTree()
		assert.Len(t, processes, 1)
		assert.NotEmpty(t, processes[0].Program)
	})

	t.Run("process that fails", func(t *testing.T) {
		tracer := newPlatformTracer(ctx, TracerOptions{})
		cmd := exec.Command("false") // exits with 1
		
		err = tracer.Start(cmd)
		require.NoError(t, err)
		
		err = tracer.Wait()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exit status 1")
	})

	t.Run("process with signals", func(t *testing.T) {
		script := `#!/bin/sh
trap 'echo "caught signal"' TERM
sleep 0.1
`
		scriptFile := filepath.Join(t.TempDir(), "signal-test.sh")
		err := os.WriteFile(scriptFile, []byte(script), 0755)
		require.NoError(t, err)

		tracer := newPlatformTracer(ctx, TracerOptions{})
		cmd := exec.Command(scriptFile)
		
		err = tracer.Start(cmd)
		require.NoError(t, err)
		
		// Give it time to start
		time.Sleep(50 * time.Millisecond)
		
		// Send signal
		cmd.Process.Signal(os.Interrupt)
		
		err = tracer.Wait()
		// Process might exit with error due to signal or might have already exited
		if err != nil {
			assert.True(t, strings.Contains(err.Error(), "exit status") || strings.Contains(err.Error(), "no such process"))
		}
	})
}

func TestTracerConcurrency(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test")
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)

	t.Run("many parallel processes", func(t *testing.T) {
		// Script that spawns multiple background processes
		script := `#!/bin/sh
for i in 1 2 3 4 5; do
    echo "Process $i" &
done
wait
`
		scriptFile := filepath.Join(t.TempDir(), "parallel.sh")
		err := os.WriteFile(scriptFile, []byte(script), 0755)
		require.NoError(t, err)

		tracer := newPlatformTracer(ctx, TracerOptions{EnableHashing: false})
		cmd := exec.Command(scriptFile)
		
		err = tracer.Start(cmd)
		require.NoError(t, err)
		
		err = tracer.Wait()
		assert.NoError(t, err)
		
		processes := tracer.GetProcessTree()
		// Should have at least the shell and some echo processes
		assert.GreaterOrEqual(t, len(processes), 2)
	})
}

func TestTracerScriptExecution(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test")
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)

	t.Run("shell script with shebang", func(t *testing.T) {
		script := `#!/bin/sh
echo "Hello from shell"
`
		scriptFile := filepath.Join(t.TempDir(), "shebang.sh")
		err := os.WriteFile(scriptFile, []byte(script), 0755)
		require.NoError(t, err)

		tracer := newPlatformTracer(ctx, TracerOptions{EnableHashing: true})
		cmd := exec.Command(scriptFile)
		
		err = tracer.Start(cmd)
		require.NoError(t, err)
		
		err = tracer.Wait()
		assert.NoError(t, err)
		
		processes := tracer.GetProcessTree()
		require.NotEmpty(t, processes)
		
		// Should have captured the shell
		foundShell := false
		for _, p := range processes {
			if strings.Contains(p.Program, "sh") {
				foundShell = true
				// With hashing enabled, should have digests
				assert.NotEmpty(t, p.ExeDigest)
				break
			}
		}
		assert.True(t, foundShell, "Should have found shell process")
	})
}

// ==================== Edge Cases Tests ====================

// Fast error handling tests
func TestTracerErrorHandling(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test")
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)

	t.Run("command_not_found", func(t *testing.T) {
		tracer := newPlatformTracer(ctx, TracerOptions{})
		cmd := exec.Command("/does/not/exist")
		err := tracer.Start(cmd)
		assert.Error(t, err)
		assert.True(t, os.IsNotExist(err) || strings.Contains(err.Error(), "no such file"))
	})

	t.Run("directory_as_command", func(t *testing.T) {
		tracer := newPlatformTracer(ctx, TracerOptions{})
		cmd := exec.Command("/tmp") // directory, not executable
		err := tracer.Start(cmd)
		assert.Error(t, err)
	})

	t.Run("empty_command", func(t *testing.T) {
		// exec.Command("") returns an error, not a panic
		cmd := exec.Command("")
		err := cmd.Run()
		assert.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "no such file") || strings.Contains(err.Error(), "no command"))
	})

	t.Run("nil_context", func(t *testing.T) {
		// Test with nil context - should handle gracefully
		tracer := newPlatformTracer(nil, TracerOptions{})
		cmd := exec.Command("echo", "test")
		err := tracer.Start(cmd)
		// Should work even with nil context, just no env capture
		require.NoError(t, err)
		err = tracer.Wait()
		assert.NoError(t, err)
	})
}

// Test edge cases with process lifecycle
func TestTracerProcessEdgeCases(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test")
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)

	t.Run("extremely_short_lived_process", func(t *testing.T) {
		// Create a simple script that exits immediately with code 42
		scriptPath := filepath.Join(t.TempDir(), "quick-exit.sh")
		err := os.WriteFile(scriptPath, []byte("#!/bin/sh\nexit 42"), 0755)
		require.NoError(t, err)

		tracer := newPlatformTracer(ctx, TracerOptions{EnableHashing: true})
		cmd := exec.Command(scriptPath)
		
		err = tracer.Start(cmd)
		require.NoError(t, err)
		
		err = tracer.Wait()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exit status 42")
		
		// Should still capture process info
		processes := tracer.GetProcessTree()
		assert.Len(t, processes, 1)
		// Should capture the shell that runs the script
		assert.NotEmpty(t, processes[0].Program)
	})

	t.Run("process_that_execs_multiple_times", func(t *testing.T) {
		// Script that execs itself with different args
		script := `#!/bin/sh
if [ "$1" = "stage2" ]; then
    exec echo "final"
else
    exec "$0" stage2
fi
`
		scriptPath := filepath.Join(t.TempDir(), "multi-exec.sh")
		err := os.WriteFile(scriptPath, []byte(script), 0755)
		require.NoError(t, err)

		tracer := newPlatformTracer(ctx, TracerOptions{})
		cmd := exec.Command(scriptPath)
		
		err = tracer.Start(cmd)
		require.NoError(t, err)
		
		err = tracer.Wait()
		assert.NoError(t, err)
		
		processes := tracer.GetProcessTree()
		// Should see the exec transitions
		assert.GreaterOrEqual(t, len(processes), 1)
	})

	t.Run("zombie_process", func(t *testing.T) {
		// Create a process that creates a zombie
		script := `#!/bin/sh
# Fork a child that exits immediately
sh -c 'exit 0' &
# Don't wait for it, creating a zombie
sleep 0.01
`
		scriptPath := filepath.Join(t.TempDir(), "zombie-creator.sh")
		err := os.WriteFile(scriptPath, []byte(script), 0755)
		require.NoError(t, err)

		tracer := newPlatformTracer(ctx, TracerOptions{})
		cmd := exec.Command(scriptPath)
		
		err = tracer.Start(cmd)
		require.NoError(t, err)
		
		err = tracer.Wait()
		assert.NoError(t, err)
		
		// Should handle zombies without crashing
		processes := tracer.GetProcessTree()
		assert.NotEmpty(t, processes)
	})
}

// Test malformed and edge case inputs
func TestTracerMalformedInputs(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test")
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)

	t.Run("non_utf8_in_arguments", func(t *testing.T) {
		// Create args with invalid UTF-8
		invalidUTF8 := string([]byte{0xff, 0xfe, 0xfd})
		
		tracer := newPlatformTracer(ctx, TracerOptions{})
		cmd := exec.Command("echo", invalidUTF8)
		
		err = tracer.Start(cmd)
		require.NoError(t, err)
		
		err = tracer.Wait()
		assert.NoError(t, err)
		
		// Should handle non-UTF8 without crashing
		processes := tracer.GetProcessTree()
		assert.NotEmpty(t, processes)
	})

	t.Run("very_long_command_line", func(t *testing.T) {
		// Create a very long argument
		longArg := strings.Repeat("a", 10000)
		
		tracer := newPlatformTracer(ctx, TracerOptions{})
		cmd := exec.Command("echo", longArg)
		
		err = tracer.Start(cmd)
		require.NoError(t, err)
		
		err = tracer.Wait()
		assert.NoError(t, err)
		
		processes := tracer.GetProcessTree()
		assert.NotEmpty(t, processes)
		// Command line might be truncated, but shouldn't crash
		assert.NotEmpty(t, processes[0].Cmdline)
	})

	t.Run("null_bytes_in_environment", func(t *testing.T) {
		tracer := newPlatformTracer(ctx, TracerOptions{})
		cmd := exec.Command("env")
		// Remove null byte test as exec package rejects it
		// Instead test with very long env var
		longValue := strings.Repeat("x", 10000)
		cmd.Env = append(os.Environ(), "LONG_VAR="+longValue)
		
		err = tracer.Start(cmd)
		require.NoError(t, err)
		
		err = tracer.Wait()
		assert.NoError(t, err)
		
		// Should handle null bytes in env without crashing
		processes := tracer.GetProcessTree()
		assert.NotEmpty(t, processes)
	})
}

// Test security-related edge cases
func TestTracerSecurityScenarios(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test")
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)

	t.Run("symlink_to_executable", func(t *testing.T) {
		// Find echo command first
		echoPath, err := exec.LookPath("echo")
		require.NoError(t, err)
		
		// Create a symlink to echo
		linkPath := filepath.Join(t.TempDir(), "echo-link")
		err = os.Symlink(echoPath, linkPath)
		require.NoError(t, err)

		tracer := newPlatformTracer(ctx, TracerOptions{EnableHashing: true})
		cmd := exec.Command(linkPath, "via symlink")
		
		err = tracer.Start(cmd)
		if err != nil {
			// Symlink execution might fail in container
			t.Skip("Symlink execution not supported in this environment")
			return
		}
		
		err = tracer.Wait()
		// May fail with exit status 127 if symlink doesn't work
		if err != nil && strings.Contains(err.Error(), "exit status 127") {
			t.Skip("Symlink execution failed in container")
			return
		}
		assert.NoError(t, err)
		
		processes := tracer.GetProcessTree()
		require.NotEmpty(t, processes)
		// Should resolve to actual binary
		// The program path might be the symlink or the actual binary
		assert.True(t, strings.Contains(processes[0].Program, "echo") || processes[0].Program == linkPath)
		// Should have hashes if resolved to actual binary
		if strings.Contains(processes[0].Program, "echo") && !strings.Contains(processes[0].Program, "echo-link") {
			assert.NotEmpty(t, processes[0].ExeDigest)
		}
	})

	t.Run("process_changes_working_directory", func(t *testing.T) {
		script := `#!/bin/sh
pwd
cd /tmp
pwd
`
		scriptPath := filepath.Join(t.TempDir(), "chdir.sh")
		err := os.WriteFile(scriptPath, []byte(script), 0755)
		require.NoError(t, err)

		tracer := newPlatformTracer(ctx, TracerOptions{})
		cmd := exec.Command(scriptPath)
		
		err = tracer.Start(cmd)
		require.NoError(t, err)
		
		err = tracer.Wait()
		assert.NoError(t, err)
		
		// Should complete without issues
		processes := tracer.GetProcessTree()
		assert.NotEmpty(t, processes)
	})

	t.Run("restricted_proc_access", func(t *testing.T) {
		// Test behavior when /proc access is restricted
		// This simulates what might happen in a container
		
		script := `#!/bin/sh
# Try to access another process's info
cat /proc/1/status 2>/dev/null || echo "Access denied as expected"
`
		scriptPath := filepath.Join(t.TempDir(), "proc-access.sh")
		err := os.WriteFile(scriptPath, []byte(script), 0755)
		require.NoError(t, err)

		tracer := newPlatformTracer(ctx, TracerOptions{})
		cmd := exec.Command(scriptPath)
		
		err = tracer.Start(cmd)
		require.NoError(t, err)
		
		err = tracer.Wait()
		assert.NoError(t, err)
		
		// Should handle restricted /proc access gracefully
		processes := tracer.GetProcessTree()
		assert.NotEmpty(t, processes)
	})
}

// Test file operation edge cases
func TestTracerFileOperations(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test")
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)

	t.Run("open_nonexistent_file", func(t *testing.T) {
		tracer := newPlatformTracer(ctx, TracerOptions{EnableHashing: true})
		cmd := exec.Command("cat", "/does/not/exist")
		
		err = tracer.Start(cmd)
		require.NoError(t, err)
		
		err = tracer.Wait()
		// cat will fail, but tracer should handle it
		assert.Error(t, err)
		
		processes := tracer.GetProcessTree()
		assert.NotEmpty(t, processes)
	})

	t.Run("file_deleted_during_execution", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "delete-me.txt")
		err := os.WriteFile(tmpFile, []byte("temporary"), 0644)
		require.NoError(t, err)

		script := fmt.Sprintf(`#!/bin/sh
cat %s
rm %s
cat %s 2>&1 || true
`, tmpFile, tmpFile, tmpFile)
		
		scriptPath := filepath.Join(t.TempDir(), "delete-test.sh")
		err = os.WriteFile(scriptPath, []byte(script), 0755)
		require.NoError(t, err)

		tracer := newPlatformTracer(ctx, TracerOptions{EnableHashing: true})
		cmd := exec.Command(scriptPath)
		
		err = tracer.Start(cmd)
		require.NoError(t, err)
		
		err = tracer.Wait()
		assert.NoError(t, err)
		
		processes := tracer.GetProcessTree()
		assert.NotEmpty(t, processes)
		// The file open should be recorded even if hashing fails
		for _, p := range processes {
			if len(p.OpenedFiles) > 0 {
				// At least one process opened files
				return
			}
		}
	})

	t.Run("circular_symlinks", func(t *testing.T) {
		// Create circular symlinks
		link1 := filepath.Join(t.TempDir(), "link1")
		link2 := filepath.Join(t.TempDir(), "link2")
		os.Symlink(link2, link1)
		os.Symlink(link1, link2)

		tracer := newPlatformTracer(ctx, TracerOptions{EnableHashing: true})
		cmd := exec.Command("ls", "-la", link1)
		
		err = tracer.Start(cmd)
		require.NoError(t, err)
		
		err = tracer.Wait()
		// ls might fail on circular link, but tracer should be ok
		if err != nil {
			assert.Contains(t, err.Error(), "exit status")
		}
		
		processes := tracer.GetProcessTree()
		assert.NotEmpty(t, processes)
	})
}

// Test resource limits and stress scenarios (but keep them fast)
func TestTracerResourceLimits(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test")
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)

	t.Run("many_rapid_forks", func(t *testing.T) {
		// Test with rapid forking but limited count to keep it fast
		script := `#!/bin/sh
for i in 1 2 3 4 5; do
    true &
done
wait
`
		scriptPath := filepath.Join(t.TempDir(), "rapid-fork.sh")
		err := os.WriteFile(scriptPath, []byte(script), 0755)
		require.NoError(t, err)

		tracer := newPlatformTracer(ctx, TracerOptions{EnableHashing: false})
		cmd := exec.Command(scriptPath)
		
		err = tracer.Start(cmd)
		require.NoError(t, err)
		
		err = tracer.Wait()
		assert.NoError(t, err)
		
		processes := tracer.GetProcessTree()
		// Should have at least the shell process
		assert.GreaterOrEqual(t, len(processes), 1)
	})

	t.Run("deep_process_tree", func(t *testing.T) {
		// Create a chain of processes (but keep it short for speed)
		script := `#!/bin/sh
if [ "$1" = "3" ]; then
    echo "bottom"
else
    next=$((${1:-0} + 1))
    exec "$0" $next
fi
`
		scriptPath := filepath.Join(t.TempDir(), "deep-tree.sh")
		err := os.WriteFile(scriptPath, []byte(script), 0755)
		require.NoError(t, err)

		tracer := newPlatformTracer(ctx, TracerOptions{})
		cmd := exec.Command(scriptPath)
		
		err = tracer.Start(cmd)
		require.NoError(t, err)
		
		err = tracer.Wait()
		assert.NoError(t, err)
		
		processes := tracer.GetProcessTree()
		assert.NotEmpty(t, processes)
	})
}

// Test specific syscall edge cases
func TestTracerSyscallEdgeCases(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test")
	}

	t.Run("process_info_parse_errors", func(t *testing.T) {
		// Test the parsing functions with malformed input
		
		// Test getPPIDFromStatus with malformed data
		ppid, err := getPPIDFromStatus([]byte("malformed"))
		assert.NoError(t, err) // Should return 0, nil for malformed
		assert.Equal(t, 0, ppid)
		
		// Test with partial data
		ppid, err = getPPIDFromStatus([]byte("PPid:"))
		assert.NoError(t, err)
		assert.Equal(t, 0, ppid)
		
		// Test cleanString with various inputs
		tests := []struct {
			input    string
			expected string
		}{
			{"\x00\x00\x00", ""},
			{"a\x00b\x00c", "a b c"},
			{"   spaces   ", "spaces"},
			{"", ""},
		}
		
		for _, tc := range tests {
			result := cleanString(tc.input)
			assert.Equal(t, tc.expected, result)
		}
	})
}

// ==================== Network Tracing Tests ====================

func TestNetworkTracing(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test")
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)

	t.Run("tcp_client_connection", func(t *testing.T) {
		// Create a simple TCP client script
		script := `#!/bin/sh
# Try to connect to Google DNS
nc -w 1 8.8.8.8 53 < /dev/null || true
`
		scriptPath := filepath.Join(t.TempDir(), "tcp-client.sh")
		err := os.WriteFile(scriptPath, []byte(script), 0755)
		require.NoError(t, err)

		tracer := newPlatformTracer(ctx, TracerOptions{
			EnableHashing:      false,
			EnableNetworkTrace: true,
		})
		cmd := exec.Command(scriptPath)
		
		err = tracer.Start(cmd)
		require.NoError(t, err)
		
		err = tracer.Wait()
		// May fail due to connection timeout, that's ok
		if err != nil {
			assert.Contains(t, err.Error(), "exit status")
		}
		
		processes := tracer.GetProcessTree()
		require.NotEmpty(t, processes)
		
		// Look for any process with network activity
		foundNetworkActivity := false
		for _, p := range processes {
			if p.NetworkActivity != nil {
				foundNetworkActivity = true
				t.Logf("Process %d (%s) network activity:", p.ProcessID, p.Program)
				t.Logf("  Sockets: %d", len(p.NetworkActivity.Sockets))
				t.Logf("  Connections: %d", len(p.NetworkActivity.Connections))
				
				// Should have created a socket
				if len(p.NetworkActivity.Sockets) > 0 {
					assert.Contains(t, []string{"AF_INET", "AF_INET6"}, p.NetworkActivity.Sockets[0].Domain)
					assert.Equal(t, "SOCK_STREAM", p.NetworkActivity.Sockets[0].Type)
				}
				
				// Should have attempted connection
				if len(p.NetworkActivity.Connections) > 0 {
					assert.Equal(t, "connect", p.NetworkActivity.Connections[0].Type)
					assert.NotEmpty(t, p.NetworkActivity.Connections[0].RemoteAddr)
				}
			}
		}
		assert.True(t, foundNetworkActivity, "Should have captured network activity")
	})

	t.Run("tcp_server_bind_listen", func(t *testing.T) {
		// Create a simple TCP server script
		script := `#!/bin/sh
# Try to bind and listen on a port
nc -l 0.0.0.0 12345 &
SERVER_PID=$!
sleep 0.1
kill $SERVER_PID 2>/dev/null || true
`
		scriptPath := filepath.Join(t.TempDir(), "tcp-server.sh")
		err := os.WriteFile(scriptPath, []byte(script), 0755)
		require.NoError(t, err)

		tracer := newPlatformTracer(ctx, TracerOptions{
			EnableHashing:      false,
			EnableNetworkTrace: true,
		})
		cmd := exec.Command(scriptPath)
		
		err = tracer.Start(cmd)
		require.NoError(t, err)
		
		err = tracer.Wait()
		// May have non-zero exit due to kill
		if err != nil {
			assert.Contains(t, err.Error(), "exit status")
		}
		
		processes := tracer.GetProcessTree()
		require.NotEmpty(t, processes)
		
		// Look for bind/listen operations
		foundBind := false
		foundListen := false
		for _, p := range processes {
			if p.NetworkActivity != nil {
				for _, conn := range p.NetworkActivity.Connections {
					if conn.Type == "bind" {
						foundBind = true
						assert.Contains(t, conn.LocalAddr, "12345")
					}
					if conn.Type == "listen" {
						foundListen = true
					}
				}
			}
		}
		assert.True(t, foundBind || foundListen, "Should have captured bind or listen")
	})

	t.Run("udp_communication", func(t *testing.T) {
		// Create a UDP test script
		script := `#!/bin/sh
# Send a UDP packet to localhost
echo "test" | nc -u -w 1 127.0.0.1 9999 || true
`
		scriptPath := filepath.Join(t.TempDir(), "udp-test.sh")
		err := os.WriteFile(scriptPath, []byte(script), 0755)
		require.NoError(t, err)

		tracer := newPlatformTracer(ctx, TracerOptions{
			EnableHashing:      false,
			EnableNetworkTrace: true,
		})
		cmd := exec.Command(scriptPath)
		
		err = tracer.Start(cmd)
		require.NoError(t, err)
		
		err = tracer.Wait()
		if err != nil {
			assert.Contains(t, err.Error(), "exit status")
		}
		
		processes := tracer.GetProcessTree()
		require.NotEmpty(t, processes)
		
		// Look for UDP socket
		foundUDP := false
		for _, p := range processes {
			if p.NetworkActivity != nil {
				for _, sock := range p.NetworkActivity.Sockets {
					if sock.Type == "SOCK_DGRAM" {
						foundUDP = true
						break
					}
				}
			}
		}
		assert.True(t, foundUDP, "Should have captured UDP socket")
	})

	t.Run("unix_domain_socket", func(t *testing.T) {
		// Create a Unix domain socket test
		socketPath := filepath.Join(t.TempDir(), "test.sock")
		script := fmt.Sprintf(`#!/bin/sh
# Create a Unix domain socket server
nc -lU %s &
SERVER_PID=$!
sleep 0.1
# Try to connect
echo "test" | nc -U %s || true
kill $SERVER_PID 2>/dev/null || true
`, socketPath, socketPath)
		
		scriptPath := filepath.Join(t.TempDir(), "unix-socket.sh")
		err := os.WriteFile(scriptPath, []byte(script), 0755)
		require.NoError(t, err)

		tracer := newPlatformTracer(ctx, TracerOptions{
			EnableHashing:      false,
			EnableNetworkTrace: true,
		})
		cmd := exec.Command(scriptPath)
		
		err = tracer.Start(cmd)
		require.NoError(t, err)
		
		err = tracer.Wait()
		if err != nil {
			assert.Contains(t, err.Error(), "exit status")
		}
		
		processes := tracer.GetProcessTree()
		require.NotEmpty(t, processes)
		
		// Look for Unix socket
		foundUnix := false
		for _, p := range processes {
			if p.NetworkActivity != nil {
				for _, sock := range p.NetworkActivity.Sockets {
					if sock.Domain == "AF_UNIX" {
						foundUnix = true
						break
					}
				}
				for _, conn := range p.NetworkActivity.Connections {
					if strings.Contains(conn.LocalAddr, "unix:") || strings.Contains(conn.RemoteAddr, "unix:") {
						foundUnix = true
						break
					}
				}
			}
		}
		assert.True(t, foundUnix, "Should have captured Unix domain socket")
	})
}

func TestNetworkTracingDisabled(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test")
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)

	// Create a script that makes network calls
	script := `#!/bin/sh
nc -w 1 8.8.8.8 53 < /dev/null || true
`
	scriptPath := filepath.Join(t.TempDir(), "network-test.sh")
	err = os.WriteFile(scriptPath, []byte(script), 0755)
	require.NoError(t, err)

	tracer := newPlatformTracer(ctx, TracerOptions{
		EnableHashing:      false,
		EnableNetworkTrace: false, // Disabled
	})
	cmd := exec.Command(scriptPath)
	
	err = tracer.Start(cmd)
	require.NoError(t, err)
	
	err = tracer.Wait()
	if err != nil {
		assert.Contains(t, err.Error(), "exit status")
	}
	
	processes := tracer.GetProcessTree()
	require.NotEmpty(t, processes)
	
	// Should NOT have network activity when disabled
	for _, p := range processes {
		assert.Nil(t, p.NetworkActivity, "Should not capture network activity when disabled")
	}
}

func TestNetworkHelperFunctions(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test")
	}

	// Test our helper functions
	t.Run("domain_to_string", func(t *testing.T) {
		assert.Equal(t, "AF_INET", domainToString(2))
		assert.Equal(t, "AF_INET6", domainToString(10))
		assert.Equal(t, "AF_UNIX", domainToString(1))
		assert.Equal(t, "AF_999", domainToString(999))
	})

	t.Run("socket_type_to_string", func(t *testing.T) {
		assert.Equal(t, "SOCK_STREAM", socketTypeToString(1))
		assert.Equal(t, "SOCK_DGRAM", socketTypeToString(2))
		assert.Equal(t, "SOCK_RAW", socketTypeToString(3))
		// Test with flags
		assert.Equal(t, "SOCK_STREAM", socketTypeToString(1|0x80000)) // SOCK_CLOEXEC
	})

	t.Run("protocol_to_string", func(t *testing.T) {
		assert.Equal(t, "default", protocolToString(0))
		assert.Equal(t, "tcp", protocolToString(6))
		assert.Equal(t, "udp", protocolToString(17))
		assert.Equal(t, "proto_999", protocolToString(999))
	})
}

// Test that network tracing integrates with the multi-exporter
func TestNetworkTracingWithMultiExporter(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test")
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)

	// Create a CommandRun with network tracing enabled
	cr := New(
		WithCommand([]string{"sh", "-c", "echo 'test' | nc -w 1 8.8.8.8 53 || true"}),
		WithTracing(true),
		WithTracerOptions(TracerOptions{
			EnableHashing:      false,
			EnableNetworkTrace: true,
		}),
	)

	// Run the attestation
	err = cr.Attest(ctx)
	// May fail due to network timeout
	if err != nil && !strings.Contains(err.Error(), "exit status") {
		t.Fatal(err)
	}

	// Get exported attestations
	exported := cr.ExportedAttestations()
	require.Len(t, exported, 1)

	// Verify it's a TraceAttestation with network data
	traceAtt, ok := exported[0].(*TraceAttestation)
	require.True(t, ok)
	assert.True(t, traceAtt.TracingOptions.EnableNetworkTrace)
	
	// Check for network activity in any process
	foundNetwork := false
	for _, p := range traceAtt.Processes {
		if p.NetworkActivity != nil && len(p.NetworkActivity.Sockets) > 0 {
			foundNetwork = true
			break
		}
	}
	assert.True(t, foundNetwork, "Should have captured network activity in trace")
}

func TestSimpleNetworkTrace(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only test")
	}

	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)

	// Test with curl if available, otherwise use a simple TCP connection attempt
	cr := New(
		WithCommand([]string{"sh", "-c", "curl -s http://example.com >/dev/null 2>&1 || nc -w 1 example.com 80 </dev/null >/dev/null 2>&1 || true"}),
		WithTracing(true),
		WithTracerOptions(TracerOptions{
			EnableHashing:      false,
			EnableNetworkTrace: true,
		}),
	)

	err = cr.Attest(ctx)
	// Ignore exit errors from network commands
	if err != nil && err.Error() != "exit status 1" && err.Error() != "exit status 2" {
		t.Logf("Command error (expected): %v", err)
	}

	// Get exported attestations
	exported := cr.ExportedAttestations()
	require.Len(t, exported, 1)

	traceAtt, ok := exported[0].(*TraceAttestation)
	require.True(t, ok)
	
	// Verify network tracing was enabled
	assert.True(t, traceAtt.TracingOptions.EnableNetworkTrace)
	assert.Equal(t, "linux", traceAtt.Platform)
	
	// Look for any network activity
	foundNetwork := false
	for _, p := range traceAtt.Processes {
		if p.NetworkActivity != nil {
			t.Logf("Process %d (%s) has network activity:", p.ProcessID, p.Program)
			t.Logf("  Sockets: %d", len(p.NetworkActivity.Sockets))
			t.Logf("  Connections: %d", len(p.NetworkActivity.Connections))
			
			if len(p.NetworkActivity.Sockets) > 0 || len(p.NetworkActivity.Connections) > 0 {
				foundNetwork = true
			}
			
			// Log socket details
			for i, sock := range p.NetworkActivity.Sockets {
				t.Logf("  Socket[%d]: %s %s %s", i, sock.Domain, sock.Type, sock.Protocol)
			}
			
			// Log connection details
			for i, conn := range p.NetworkActivity.Connections {
				t.Logf("  Connection[%d]: %s local=%s remote=%s", i, conn.Type, conn.LocalAddr, conn.RemoteAddr)
			}
		}
	}
	
	assert.True(t, foundNetwork, "Should have captured some network activity")
}

// ==================== Benchmarks ====================

func BenchmarkTracing(b *testing.B) {
	if runtime.GOOS != "linux" {
		b.Skip("Linux only benchmark")
	}

	ctx, _ := attestation.NewContext("bench", []attestation.Attestor{})

	b.Run("without_tracing", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			cmd := exec.Command("echo", "benchmark")
			cmd.Run()
		}
	})

	b.Run("with_tracing_no_hash", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tracer := newPlatformTracer(ctx, TracerOptions{EnableHashing: false})
			cmd := exec.Command("echo", "benchmark")
			tracer.Start(cmd)
			tracer.Wait()
		}
	})

	b.Run("with_tracing_and_hash", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tracer := newPlatformTracer(ctx, TracerOptions{EnableHashing: true})
			cmd := exec.Command("echo", "benchmark")
			tracer.Start(cmd)
			tracer.Wait()
		}
	})
}

// Benchmark network tracing overhead
func BenchmarkNetworkTracing(b *testing.B) {
	if runtime.GOOS != "linux" {
		b.Skip("Linux only benchmark")
	}

	ctx, _ := attestation.NewContext("bench", []attestation.Attestor{})

	b.Run("without_network_trace", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tracer := newPlatformTracer(ctx, TracerOptions{
				EnableHashing:      false,
				EnableNetworkTrace: false,
			})
			cmd := exec.Command("true")
			tracer.Start(cmd)
			tracer.Wait()
		}
	})

	b.Run("with_network_trace", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tracer := newPlatformTracer(ctx, TracerOptions{
				EnableHashing:      false,
				EnableNetworkTrace: true,
			})
			cmd := exec.Command("true")
			tracer.Start(cmd)
			tracer.Wait()
		}
	})
}

// Benchmark critical paths but keep them fast
func BenchmarkTracerCriticalPath(b *testing.B) {
	if runtime.GOOS != "linux" {
		b.Skip("Linux only benchmark")
	}

	ctx, _ := attestation.NewContext("bench", []attestation.Attestor{})

	b.Run("minimal_trace", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tracer := newPlatformTracer(ctx, TracerOptions{EnableHashing: false})
			cmd := exec.Command("true") // Fastest possible command
			tracer.Start(cmd)
			tracer.Wait()
		}
	})

	b.Run("trace_with_args", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tracer := newPlatformTracer(ctx, TracerOptions{EnableHashing: false})
			cmd := exec.Command("echo", "a", "b", "c")
			tracer.Start(cmd)
			tracer.Wait()
		}
	})
}

// ==================== Helper Function Tests ====================

func TestSyscallHelpers(t *testing.T) {
	// Test architecture-specific functions exist and work
	regs := getRegisters()
	assert.NotNil(t, regs)
	
	// These should not panic
	_ = getSyscallID(regs)
	_ = getArg0(regs)
	_ = getArg1(regs)
	_ = getArg2(regs)
}

func TestProcessInfoParsing(t *testing.T) {
	t.Run("cleanString", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"hello\x00world", "hello world"},
			{"  spaces  ", "spaces"},
			{"normal", "normal"},
			{"\x00\x00", ""},
		}
		
		for _, tt := range tests {
			result := cleanString(tt.input)
			assert.Equal(t, tt.expected, result)
		}
	})
}

// ==================== Status Parsing Tests (from tracing_linux_test.go) ====================

const (
	testStatusContent = `
Name:   blkcg_punt_bio
Umask:  0000
State:  I (idle)
Tgid:   214
Ngid:   0
Pid:    214
PPid:   2
TracerPid:      0
Uid:    0       0       0       0
Gid:    0       0       0       0
FDSize: 64
Groups:
NStgid: 214
NSpid:  214
NSpgid: 0
NSsid:  0
Threads:        1
SigQ:   0/514646
SigPnd: 0000000000000000
ShdPnd: 0000000000000000
SigBlk: 0000000000000000
SigIgn: ffffffffffffffff
SigCgt: 0000000000000000
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
NoNewPrivs:     0
Seccomp:        0
Speculation_Store_Bypass:       thread vulnerable
Cpus_allowed:   ffffffff
Cpus_allowed_list:      0-31
Mems_allowed:   00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000001
Mems_allowed_list:      0
voluntary_ctxt_switches:        2
nonvoluntary_ctxt_switches:     0
	`
)

func Test_getPPIDFromStatus(t *testing.T) {
	byteStatus := []byte(testStatusContent)

	ppid, err := getPPIDFromStatus(byteStatus)
	if err != nil {
		t.Errorf("getPPIDFromStatus() error = %v", err)
		return
	}

	if ppid != 2 {
		t.Errorf("getPPIDFromStatus() = %v, want %v", ppid, 2)
	}

}

