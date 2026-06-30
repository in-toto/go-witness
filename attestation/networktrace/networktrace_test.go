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

package networktrace

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/commandrun"
	"github.com/in-toto/go-witness/attestation/networktrace/types"
	"github.com/in-toto/go-witness/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const (
	testServerPort = 19876
	testProxyPort  = 18888
)

func TestNew(t *testing.T) {
	attestor := New()

	assert.Equal(t, Name, attestor.Name())
	assert.Equal(t, Type, attestor.Type())
	assert.Equal(t, RunType, attestor.RunType())
}

func TestNewWithConfig(t *testing.T) {
	config := types.Config{
		ProxyPort:        9999,
		ProxyBindIPv4:    "127.0.0.1",
		ObserveChildTree: false,
		Payload: types.PayloadConfig{
			RecordPayload:     true,
			RecordPayloadHash: true,
			MaxPayloadSize:    2048,
		},
	}

	attestor := NewWithConfig(config)

	assert.Equal(t, uint16(9999), attestor.config.ProxyPort)
	assert.Equal(t, "127.0.0.1", attestor.config.ProxyBindIPv4)
	assert.False(t, attestor.config.ObserveChildTree)
	assert.True(t, attestor.config.Payload.RecordPayload)
}

func TestDefaultConfig(t *testing.T) {
	config := types.DefaultConfig()

	assert.Equal(t, uint16(types.DefaultProxyPort), config.ProxyPort)
	assert.Equal(t, types.DefaultProxyBindIPv4, config.ProxyBindIPv4)
	assert.True(t, config.ObserveChildTree)
	assert.False(t, config.Payload.RecordPayload)
	assert.True(t, config.Payload.RecordPayloadHash)
	assert.Equal(t, int64(1024*1024), config.Payload.MaxPayloadSize)
}

func TestSchema(t *testing.T) {
	attestor := New()
	schema := attestor.Schema()

	assert.NotNil(t, schema)
}

func TestComputeSummary(t *testing.T) {
	connections := []types.Connection{
		{
			Protocol:      "tcp",
			BytesSent:     100,
			BytesReceived: 200,
			Destination: types.Endpoint{
				IP:       net.ParseIP("192.168.1.1"),
				Port:     80,
				Hostname: "example.com",
			},
		},
		{
			Protocol:      "tcp",
			BytesSent:     50,
			BytesReceived: 100,
			Destination: types.Endpoint{
				IP:       net.ParseIP("192.168.1.2"),
				Port:     443,
				Hostname: "example.org",
			},
		},
	}

	summary := types.ComputeSummary(connections)

	assert.Equal(t, 2, summary.TotalConnections)
	assert.Equal(t, 2, summary.ProtocolCounts["tcp"])
	assert.Equal(t, uint64(150), summary.TotalBytesSent)
	assert.Equal(t, uint64(300), summary.TotalBytesReceived)
	assert.Len(t, summary.UniqueHosts, 2)
	assert.Len(t, summary.UniqueIPs, 2)
}

func TestComputeSummaryEmpty(t *testing.T) {
	summary := types.ComputeSummary(nil)

	assert.Equal(t, 0, summary.TotalConnections)
	assert.Empty(t, summary.ProtocolCounts)
	assert.Empty(t, summary.UniqueHosts)
	assert.Empty(t, summary.UniqueIPs)
}

func skipIfNotRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Skipping test: requires root privileges for BPF and network interception")
	}
}

func assertNoAttestorErrors(t *testing.T, ctx *attestation.AttestationContext) {
	t.Helper()
	for _, ca := range ctx.CompletedAttestors() {
		if ca.Error != nil {
			t.Errorf("attestor %s failed unexpectedly: %v", ca.Attestor.Name(), ca.Error)
		}
	}
}

type testTCPServer struct {
	listener     net.Listener
	port         int
	response     []byte
	receivedData chan []byte
	done         chan struct{}
}

func newTestTCPServer(t *testing.T, port int, response []byte) *testTCPServer {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(t, err)

	server := &testTCPServer{
		listener:     listener,
		port:         port,
		response:     response,
		receivedData: make(chan []byte, 1),
		done:         make(chan struct{}),
	}

	go server.serve()
	return server
}

func (s *testTCPServer) serve() {
	defer close(s.done)
	defer s.listener.Close()

	conn, err := s.listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	data, err := io.ReadAll(conn)
	if err != nil {
		s.receivedData <- nil
		return
	}
	s.receivedData <- data

	if len(s.response) > 0 {
		_, _ = conn.Write(s.response)
	}
}

func (s *testTCPServer) wait() {
	<-s.done
}

func TestIntegrationNetworkTrace(t *testing.T) {
	skipIfNotRoot(t)

	clientRequest := "PING"
	serverResponse := "PONG"

	requestHash := sha256.Sum256([]byte(clientRequest))
	requestHashHex := hex.EncodeToString(requestHash[:])
	responseHash := sha256.Sum256([]byte(serverResponse))
	responseHashHex := hex.EncodeToString(responseHash[:])

	server := newTestTCPServer(t, testServerPort, []byte(serverResponse))
	defer server.wait()

	config := types.Config{
		ProxyPort:        testProxyPort,
		ProxyBindIPv4:    "127.0.0.1",
		ObserveChildTree: true,
		Payload: types.PayloadConfig{
			RecordPayload:     true,
			RecordPayloadHash: true,
			MaxPayloadSize:    1024 * 1024,
		},
	}

	networkAttestor := NewWithConfig(config)

	cmd := commandrun.New(
		commandrun.WithCommand([]string{
			"sh", "-c",
			fmt.Sprintf("echo -n '%s' | nc -q 1 127.0.0.1 %d", clientRequest, testServerPort),
		}),
		commandrun.WithSilent(false),
	)

	ctx, err := attestation.NewContext("test-networktrace", []attestation.Attestor{cmd, networkAttestor})
	require.NoError(t, err)

	err = ctx.RunAttestors()
	require.NoError(t, err)
	assertNoAttestorErrors(t, ctx)

	receivedData := <-server.receivedData
	assert.Equal(t, []byte(clientRequest), receivedData, "Server should receive exact request data")

	assert.False(t, networkAttestor.NetworkTrace.StartTime.IsZero())
	assert.False(t, networkAttestor.NetworkTrace.EndTime.IsZero())
	assert.True(t, networkAttestor.NetworkTrace.EndTime.After(networkAttestor.NetworkTrace.StartTime))

	// Realistically the server should see only one connection
	assert.Len(t, networkAttestor.NetworkTrace.Connections, 1, "Should record one connection")

	conn := networkAttestor.NetworkTrace.Connections[0]
	assert.Equal(t, "tcp", conn.Protocol)
	assert.Equal(t, uint16(testServerPort), conn.Destination.Port)
	assert.Equal(t, uint64(len(clientRequest)), conn.BytesSent)
	assert.Equal(t, uint64(len(serverResponse)), conn.BytesReceived)

	// Verify process info
	assert.NotZero(t, conn.Process.PID, "Connection should record process PID")
	assert.Equal(t, "nc", conn.Process.Comm, "Connection should record process command name")
	assert.NotZero(t, conn.Process.CgroupID, "Connection should record process CgroupID")

	// Verify payloads
	assert.Len(t, conn.TCPPayloads, 2, "Should record two payloads (request and response)")

	// Verify client to server payload
	clientPayload := conn.TCPPayloads[0]
	assert.Equal(t, "client_to_server", clientPayload.Direction)
	assert.Equal(t, int64(len(clientRequest)), clientPayload.Payload.Size)
	assert.Equal(t, clientRequest, string(clientPayload.Payload.Data))
	assert.Equal(t, requestHashHex, clientPayload.Payload.Hash)

	// Verify server to client payload
	serverPayload := conn.TCPPayloads[1]
	assert.Equal(t, "server_to_client", serverPayload.Direction)
	assert.Equal(t, int64(len(serverResponse)), serverPayload.Payload.Size)
	assert.Equal(t, serverResponse, string(serverPayload.Payload.Data))
	assert.Equal(t, responseHashHex, serverPayload.Payload.Hash)
}

func TestIntegrationZeroByteConnection(t *testing.T) {
	skipIfNotRoot(t)

	const zeroByteServerPort = 19877

	server := newTestTCPServer(t, zeroByteServerPort, nil)
	defer server.wait()

	config := types.Config{
		ProxyPort:        testProxyPort + 1,
		ProxyBindIPv4:    "127.0.0.1",
		ObserveChildTree: true,
		Payload: types.PayloadConfig{
			RecordPayload:     true,
			RecordPayloadHash: true,
			MaxPayloadSize:    1024,
		},
	}

	networkAttestor := NewWithConfig(config)

	// Connect but send nothing (< /dev/null)
	cmd := commandrun.New(
		commandrun.WithCommand([]string{
			"sh", "-c",
			fmt.Sprintf("nc -w 1 127.0.0.1 %d < /dev/null || true", zeroByteServerPort),
		}),
		commandrun.WithSilent(false),
	)

	ctx, err := attestation.NewContext("test-zero", []attestation.Attestor{cmd, networkAttestor})
	require.NoError(t, err)

	err = ctx.RunAttestors()
	require.NoError(t, err)
	assertNoAttestorErrors(t, ctx)

	receivedData := <-server.receivedData
	assert.Equal(t, []byte{}, receivedData, "Server should receive zero-byte data")

	assert.Len(t, networkAttestor.NetworkTrace.Connections, 1, "Should record one connection")
	conn := networkAttestor.NetworkTrace.Connections[0]
	assert.Equal(t, uint64(0), conn.BytesSent, "Should record zero bytes sent")
	assert.Equal(t, uint64(0), conn.BytesReceived, "Should record zero bytes received")
	assert.Len(t, conn.TCPPayloads, 2, "Should record two payloads (even if zero-byte)")

	// Verify client to server payload
	clientPayload := conn.TCPPayloads[0]
	assert.Equal(t, "client_to_server", clientPayload.Direction)
	assert.Equal(t, int64(0), clientPayload.Payload.Size)
	assert.Equal(t, "", string(clientPayload.Payload.Data))
	assert.Equal(t, "", clientPayload.Payload.Hash)

	// Verify server to client payload
	serverPayload := conn.TCPPayloads[1]
	assert.Equal(t, "server_to_client", serverPayload.Direction)
	assert.Equal(t, int64(0), serverPayload.Payload.Size)
	assert.Equal(t, "", string(serverPayload.Payload.Data))
	assert.Equal(t, "", serverPayload.Payload.Hash)
}

func TestIntegrationHangingConnectionTeardown(t *testing.T) {
	skipIfNotRoot(t)

	const hangServerPort = 19878

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", hangServerPort))
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		// Read a little data so we know the client connected
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)

		// simulate a server that keeps the connection alive indefinitely.
		time.Sleep(1 * time.Hour)
	}()

	config := types.Config{
		ProxyPort:        testProxyPort + 2,
		ProxyBindIPv4:    "127.0.0.1",
		ObserveChildTree: true,
		Payload: types.PayloadConfig{
			RecordPayload:     true,
			RecordPayloadHash: true,
			MaxPayloadSize:    1024,
		},
	}
	networkAttestor := NewWithConfig(config)

	// making sure the process itself does not hang
	cmd := commandrun.New(
		commandrun.WithCommand([]string{
			"timeout", "0.2", "sh", "-c",
			fmt.Sprintf("echo 'X' | nc 127.0.0.1 %d", hangServerPort),
		}),
		commandrun.WithSilent(false),
	)

	ctx, err := attestation.NewContext("test-hang", []attestation.Attestor{cmd, networkAttestor})
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		done <- ctx.RunAttestors()
	}()

	select {
	case err := <-done:
		require.NoError(t, err, "Attestors should run successfully and shut down cleanly")

		// command run actually fails due to timeout
		foundCmdError := false
		for _, ca := range ctx.CompletedAttestors() {
			if ca.Attestor.Name() == "command-run" {
				require.Error(t, ca.Error, "Expected command-run attestor to fail due to SIGKILL")
				assert.Contains(t, ca.Error.Error(), "exit status 124", "Expected attestor to fail due to SIGKILL")
				foundCmdError = true
				break
			}
		}
		require.True(t, foundCmdError, "command-run attestor not found in completed attestors")

	case <-time.After(10 * time.Second):
		t.Fatal("DEADLOCK DETECTED: Test timed out! The proxy failed to forcefully close lingering connections during shutdown, causing io.Copy to block forever.")
	}
}

func TestIntegrationExecveGhostThread(t *testing.T) {
	skipIfNotRoot(t)

	// This test forces a multi-threaded program to call execve from a background thread.
	const testPort = 19880
	server := newTestTCPServer(t, testPort, []byte("PONG"))
	defer server.wait()

	config := types.Config{
		ProxyPort:        testProxyPort + 3,
		ProxyBindIPv4:    "127.0.0.1",
		ObserveChildTree: true,
		Payload: types.PayloadConfig{
			RecordPayload: true,
		},
	}
	networkAttestor := NewWithConfig(config)

	pythonScript := fmt.Sprintf(`
import os, threading, time
def do_exec():
    time.sleep(0.1) # Brief pause to ensure the thread fully detaches
    os.execlp("sh", "sh", "-c", "echo 'GHOST' | nc -w 1 127.0.0.1 %d")
threading.Thread(target=do_exec).start()
while True:
    time.sleep(1) # Keep main thread alive to be swapped
`, testPort)

	// Write the script to a temp file
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "ghost.py")
	require.NoError(t, os.WriteFile(scriptPath, []byte(pythonScript), 0644))

	cmd := commandrun.New(
		commandrun.WithCommand([]string{"python3", scriptPath}),
		commandrun.WithSilent(false),
	)

	ctx, err := attestation.NewContext("test-ghost-thread", []attestation.Attestor{cmd, networkAttestor})
	require.NoError(t, err)

	err = ctx.RunAttestors()
	require.NoError(t, err) // Should not hang or error out
	assertNoAttestorErrors(t, ctx)

	// Assert the proxy successfully tracked the ghost thread's execution
	assert.Len(t, networkAttestor.NetworkTrace.Connections, 1, "Should intercept connection from rescued thread")
}

func TestIntegrationSIGKILLException(t *testing.T) {
	skipIfNotRoot(t)

	config := types.DefaultConfig()
	config.ProxyPort = testProxyPort + 4
	networkAttestor := NewWithConfig(config)

	pidFile := filepath.Join(t.TempDir(), "witness_test_sigkill.pid")

	cmd := commandrun.New(
		commandrun.WithCommand([]string{"sh", "-c", fmt.Sprintf("echo $$ > %s && exec sleep 100", pidFile)}),
		commandrun.WithSilent(false),
	)

	ctx, err := attestation.NewContext("test-sigkill", []attestation.Attestor{cmd, networkAttestor})
	require.NoError(t, err)

	go func() {
		var pid int
		for range 50 { // Poll for up to 5 seconds
			time.Sleep(100 * time.Millisecond)
			data, err := os.ReadFile(pidFile)
			if err == nil && len(data) > 0 {
				_, _ = fmt.Sscanf(string(data), "%d", &pid)
				if pid > 0 {
					err = unix.Kill(pid, unix.SIGKILL)
					assert.NoError(t, err, "Failed to send SIGKILL to test process")
					return
				}
			}
		}
	}()

	err = ctx.RunAttestors()
	// Note: RunAttestors() returns nil even when attestors fail.
	// Errors are stored in CompletedAttestors(), so we check there.
	require.NoError(t, err, "RunAttestors should not return error")

	// Verify command-run attestor failed due to SIGKILL
	foundCmdError := false
	for _, ca := range ctx.CompletedAttestors() {
		if ca.Attestor.Name() == "command-run" {
			require.Error(t, ca.Error, "Expected command-run attestor to fail due to SIGKILL")
			assert.Contains(t, ca.Error.Error(), "exit status 137", "Expected attestor to fail due to SIGKILL")
			foundCmdError = true
			break
		}
	}
	require.True(t, foundCmdError, "command-run attestor not found in completed attestors")

	// The fallback pre-exit hooks must have run
	assert.False(t, networkAttestor.NetworkTrace.EndTime.IsZero(), "Proxy teardown should still execute via SIGKILL fallback")
}

func TestIntegrationNestedNamespaceTracking(t *testing.T) {
	skipIfNotRoot(t)

	const nsTestPort = 19881
	server := newTestTCPServer(t, nsTestPort, []byte("PONG"))
	defer server.wait()

	config := types.Config{
		ProxyPort:        testProxyPort + 5,
		ProxyBindIPv4:    "127.0.0.1",
		ObserveChildTree: true,
		Payload:          types.PayloadConfig{RecordPayload: true},
	}
	networkAttestor := NewWithConfig(config)

	// unshare -p -f creates a new isolated PID namespace for the command
	cmd := commandrun.New(
		commandrun.WithCommand([]string{
			"unshare", "-p", "-f", "--mount-proc", "sh", "-c",
			fmt.Sprintf("echo 'NS_TEST' | nc -w 1 127.0.0.1 %d", nsTestPort),
		}),
		commandrun.WithSilent(false),
	)

	ctx, err := attestation.NewContext("test-namespace", []attestation.Attestor{cmd, networkAttestor})
	require.NoError(t, err)

	err = ctx.RunAttestors()
	require.NoError(t, err)
	assertNoAttestorErrors(t, ctx)

	// If get_tid_ns() works correctly, the proxy will capture the connection.
	assert.Len(t, networkAttestor.NetworkTrace.Connections, 1, "Should intercept connection inside nested PID namespace")
}

func TestIntegrationOrphanedProcessSurvival(t *testing.T) {
	skipIfNotRoot(t)

	const orphanTestPort = 19882
	server := newTestTCPServer(t, orphanTestPort, []byte("PONG"))
	defer server.wait()

	config := types.Config{
		ProxyPort:        testProxyPort + 8,
		ProxyBindIPv4:    "127.0.0.1",
		ObserveChildTree: true,
		Payload:          types.PayloadConfig{RecordPayload: true},
	}
	networkAttestor := NewWithConfig(config)

	// The parent script spawns a background task and immediately exits.
	// The child sleeps for 1 second (becoming an orphan reparented to PID 1), then connects.
	cmd := commandrun.New(
		commandrun.WithCommand([]string{
			"sh", "-c", fmt.Sprintf("(sleep 3 && echo 'ORPHAN' | nc -w 1 127.0.0.1 %d) & exit 0", orphanTestPort),
		}),
		commandrun.WithSilent(false),
	)

	ctx, err := attestation.NewContext("test-orphan", []attestation.Attestor{cmd, networkAttestor})
	require.NoError(t, err)

	err = ctx.RunAttestors()
	require.NoError(t, err)
	assertNoAttestorErrors(t, ctx)

	assert.Len(t, networkAttestor.NetworkTrace.Connections, 1, "Should intercept connection from orphaned background process")
}

func TestIntegrationDeepNestingAndExecveSwap(t *testing.T) {
	skipIfNotRoot(t)

	// We set up three distinct servers to verify three network calls happening
	// at different stages of the process tree's lifecycle and nesting depth.
	port1, port2, port3 := 19890, 19891, 19892
	srv1 := newTestTCPServer(t, port1, []byte("ACK1"))
	srv2 := newTestTCPServer(t, port2, []byte("ACK2"))
	srv3 := newTestTCPServer(t, port3, []byte("ACK3"))
	defer srv1.wait()
	defer srv2.wait()
	defer srv3.wait()

	config := types.Config{
		ProxyPort:        testProxyPort + 9,
		ProxyBindIPv4:    "127.0.0.1",
		ObserveChildTree: true,
		Payload: types.PayloadConfig{
			RecordPayload: true,
		},
	}
	networkAttestor := NewWithConfig(config)

	// This python script compresses the CI pipeline lifecycle:
	// 1. Python Main Thread connects to Port 1
	// 2. Python Background Thread calls execve, swapping identity to 'sh'
	// 3. The newly exec'd 'sh' connects to Port 2
	// 4. The 'sh' spawns a deeply nested subshell 'sh', which connects to Port 3
	pythonScript := fmt.Sprintf(`
import os, threading, socket, time

# Connection 1: Synchronous call from the main thread
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", %d))
s.sendall(b"PAYLOAD_1")
s.close()

def do_exec():
    # Execute Connection 2 natively, then spawn a nested shell for Connection 3
    cmd = "echo 'PAYLOAD_2' | nc -w 1 127.0.0.1 %d && sh -c 'echo \"PAYLOAD_3\" | nc -w 1 127.0.0.1 %d'"
    os.execlp("sh", "sh", "-c", cmd)

threading.Thread(target=do_exec).start()

# Wait to be slaughtered by the kernel during the swap
while True:
    time.sleep(1)
`, port1, port2, port3)

	// Write the script to a temp file to completely bypass shell quoting rules
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "deep_nest.py")
	require.NoError(t, os.WriteFile(scriptPath, []byte(pythonScript), 0644))

	// Wrap the Python script in multiple levels of shell nesting using the file path
	deepNestCmd := fmt.Sprintf("sh -c \"sh -c 'python3 %s'\"", scriptPath)

	cmd := commandrun.New(
		commandrun.WithCommand([]string{"sh", "-c", deepNestCmd}),
		commandrun.WithSilent(false),
	)

	ctx, err := attestation.NewContext("test-deep-nesting-exec", []attestation.Attestor{cmd, networkAttestor})
	require.NoError(t, err)

	err = ctx.RunAttestors()
	require.NoError(t, err)
	assertNoAttestorErrors(t, ctx)

	// We must have exactly 3 recorded connections.
	connections := networkAttestor.NetworkTrace.Connections
	assert.Len(t, connections, 3, "Should intercept exactly 3 connections across the nested execve lifecycle")

	// Validate the payloads to ensure the proxy successfully routed and hashed every step
	// of the multi-threaded identity swap.
	var payloads []string
	for _, conn := range connections {
		if len(conn.TCPPayloads) > 0 {
			for _, p := range conn.TCPPayloads {
				if p.Direction == "client_to_server" {
					payloads = append(payloads, string(p.Payload.Data))
				}
			}
		}
	}

	assert.Contains(t, payloads, "PAYLOAD_1", "Failed to capture pre-execve payload")
	assert.Contains(t, payloads, "PAYLOAD_2\n", "Failed to capture post-execve payload (Ghost rescue failed)")
	assert.Contains(t, payloads, "PAYLOAD_3\n", "Failed to capture deeply nested payload spawned by rescued ghost")
}

func TestMain(m *testing.M) {
	log.SetLogger(log.ConsoleLogger{})
	ec := m.Run()
	os.Exit(ec)
}
