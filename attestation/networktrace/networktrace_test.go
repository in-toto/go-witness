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
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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
		EnableHTTPInspection: false,
	}

	attestor := NewWithConfig(config)

	assert.Equal(t, uint16(9999), attestor.NetworkTrace.Config.ProxyPort)
	assert.Equal(t, "127.0.0.1", attestor.NetworkTrace.Config.ProxyBindIPv4)
	assert.False(t, attestor.NetworkTrace.Config.ObserveChildTree)
	assert.True(t, attestor.NetworkTrace.Config.Payload.RecordPayload)
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

func newCmd(withTracing bool, command []string) *commandrun.CommandRun {
	opts := []commandrun.Option{
		commandrun.WithCommand(command),
		commandrun.WithSilent(false),
	}
	if withTracing {
		opts = append(opts, commandrun.WithTracing(true))
	}
	return commandrun.New(opts...)
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
	for _, withTracing := range []bool{false, true} {
		name := "hooks-only"
		if withTracing {
			name = "full-tracing"
		}
		t.Run(name, func(t *testing.T) {
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
				EnableHTTPInspection: false,
			}

			networkAttestor := NewWithConfig(config)

			cmd := newCmd(withTracing, []string{
				"sh", "-c",
				fmt.Sprintf("echo -n '%s' | nc -q 1 127.0.0.1 %d", clientRequest, testServerPort),
			})

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

			assert.Len(t, networkAttestor.NetworkTrace.Connections, 1, "Should record one connection")

			conn := networkAttestor.NetworkTrace.Connections[0]
			assert.Equal(t, "tcp", conn.Protocol)
			assert.Equal(t, uint16(testServerPort), conn.Destination.Port)
			assert.Equal(t, uint64(len(clientRequest)), conn.BytesSent)
			assert.Equal(t, uint64(len(serverResponse)), conn.BytesReceived)

			assert.NotZero(t, conn.Process.PID, "Connection should record process PID")
			assert.Equal(t, "nc", conn.Process.Comm, "Connection should record process command name")
			assert.NotZero(t, conn.Process.CgroupID, "Connection should record process CgroupID")

			assert.Len(t, conn.TCPPayloads, 2, "Should record two payloads (request and response)")

			clientPayload := conn.TCPPayloads[0]
			assert.Equal(t, "client_to_server", clientPayload.Direction)
			assert.Equal(t, int64(len(clientRequest)), clientPayload.Payload.Size)
			assert.Equal(t, clientRequest, string(clientPayload.Payload.Data))
			assert.Equal(t, requestHashHex, clientPayload.Payload.Hash)

			serverPayload := conn.TCPPayloads[1]
			assert.Equal(t, "server_to_client", serverPayload.Direction)
			assert.Equal(t, int64(len(serverResponse)), serverPayload.Payload.Size)
			assert.Equal(t, serverResponse, string(serverPayload.Payload.Data))
			assert.Equal(t, responseHashHex, serverPayload.Payload.Hash)
		})
	}
}

func TestIntegrationZeroByteConnection(t *testing.T) {
	for _, withTracing := range []bool{false, true} {
		name := "hooks-only"
		if withTracing {
			name = "full-tracing"
		}
		t.Run(name, func(t *testing.T) {
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
				EnableHTTPInspection: false,
			}

			networkAttestor := NewWithConfig(config)

			cmd := newCmd(withTracing, []string{
				"sh", "-c",
				fmt.Sprintf("nc -w 1 127.0.0.1 %d < /dev/null || true", zeroByteServerPort),
			})

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

			clientPayload := conn.TCPPayloads[0]
			assert.Equal(t, "client_to_server", clientPayload.Direction)
			assert.Equal(t, int64(0), clientPayload.Payload.Size)
			assert.Equal(t, "", string(clientPayload.Payload.Data))
			assert.Equal(t, "", clientPayload.Payload.Hash)

			serverPayload := conn.TCPPayloads[1]
			assert.Equal(t, "server_to_client", serverPayload.Direction)
			assert.Equal(t, int64(0), serverPayload.Payload.Size)
			assert.Equal(t, "", string(serverPayload.Payload.Data))
			assert.Equal(t, "", serverPayload.Payload.Hash)
		})
	}
}

func TestIntegrationHangingConnectionTeardown(t *testing.T) {
	for _, withTracing := range []bool{false, true} {
		name := "hooks-only"
		if withTracing {
			name = "full-tracing"
		}
		t.Run(name, func(t *testing.T) {
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
				buf := make([]byte, 1)
				_, _ = conn.Read(buf)

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
				EnableHTTPInspection: false,
			}
			networkAttestor := NewWithConfig(config)

			cmd := newCmd(withTracing, []string{
				"timeout", "0.2", "sh", "-c",
				fmt.Sprintf("echo 'X' | nc 127.0.0.1 %d", hangServerPort),
			})

			ctx, err := attestation.NewContext("test-hang", []attestation.Attestor{cmd, networkAttestor})
			require.NoError(t, err)

			done := make(chan error, 1)
			go func() {
				done <- ctx.RunAttestors()
			}()

			select {
			case err := <-done:
				require.NoError(t, err, "Attestors should run successfully and shut down cleanly")

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
		})
	}
}

func TestIntegrationExecveGhostThread(t *testing.T) {
	for _, withTracing := range []bool{false, true} {
		name := "hooks-only"
		if withTracing {
			name = "full-tracing"
		}
		t.Run(name, func(t *testing.T) {
			skipIfNotRoot(t)

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

			tmpDir := t.TempDir()
			scriptPath := filepath.Join(tmpDir, "ghost.py")
			require.NoError(t, os.WriteFile(scriptPath, []byte(pythonScript), 0644))

			cmd := newCmd(withTracing, []string{"python3", scriptPath})

			ctx, err := attestation.NewContext("test-ghost-thread", []attestation.Attestor{cmd, networkAttestor})
			require.NoError(t, err)

			err = ctx.RunAttestors()
			require.NoError(t, err)
			assertNoAttestorErrors(t, ctx)

			assert.Len(t, networkAttestor.NetworkTrace.Connections, 1, "Should intercept connection from rescued thread")
		})
	}
}

func TestIntegrationSIGKILLException(t *testing.T) {
	for _, withTracing := range []bool{false, true} {
		name := "hooks-only"
		if withTracing {
			name = "full-tracing"
		}
		t.Run(name, func(t *testing.T) {
			skipIfNotRoot(t)

			config := types.DefaultConfig()
			config.ProxyPort = testProxyPort + 4
			networkAttestor := NewWithConfig(config)

			pidFile := filepath.Join(t.TempDir(), "witness_test_sigkill.pid")

			cmd := newCmd(withTracing, []string{"sh", "-c", fmt.Sprintf("echo $$ > %s && exec sleep 100", pidFile)})

			ctx, err := attestation.NewContext("test-sigkill", []attestation.Attestor{cmd, networkAttestor})
			require.NoError(t, err)

			go func() {
				var pid int
				for range 50 {
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
			require.NoError(t, err, "RunAttestors should not return error")

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

			assert.False(t, networkAttestor.NetworkTrace.EndTime.IsZero(), "Proxy teardown should still execute via SIGKILL fallback")
		})
	}
}

func TestIntegrationNestedNamespaceTracking(t *testing.T) {
	for _, withTracing := range []bool{false, true} {
		name := "hooks-only"
		if withTracing {
			name = "full-tracing"
		}
		t.Run(name, func(t *testing.T) {
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

			cmd := newCmd(withTracing, []string{
				"unshare", "-p", "-f", "--mount-proc", "sh", "-c",
				fmt.Sprintf("echo 'NS_TEST' | nc -w 1 127.0.0.1 %d", nsTestPort),
			})

			ctx, err := attestation.NewContext("test-namespace", []attestation.Attestor{cmd, networkAttestor})
			require.NoError(t, err)

			err = ctx.RunAttestors()
			require.NoError(t, err)
			assertNoAttestorErrors(t, ctx)

			assert.Len(t, networkAttestor.NetworkTrace.Connections, 1, "Should intercept connection inside nested PID namespace")
		})
	}
}

func TestIntegrationOrphanedProcessSurvival(t *testing.T) {
	for _, withTracing := range []bool{false, true} {
		name := "hooks-only"
		if withTracing {
			name = "full-tracing"
		}
		t.Run(name, func(t *testing.T) {
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

			cmd := newCmd(withTracing, []string{
				"sh", "-c", fmt.Sprintf("(sleep 3 && echo 'ORPHAN' | nc -w 1 127.0.0.1 %d) & exit 0", orphanTestPort),
			})

			ctx, err := attestation.NewContext("test-orphan", []attestation.Attestor{cmd, networkAttestor})
			require.NoError(t, err)

			err = ctx.RunAttestors()
			require.NoError(t, err)
			assertNoAttestorErrors(t, ctx)

			assert.Len(t, networkAttestor.NetworkTrace.Connections, 1, "Should intercept connection from orphaned background process")
		})
	}
}

func TestIntegrationDeepNestingAndExecveSwap(t *testing.T) {
	for _, withTracing := range []bool{false, true} {
		name := "hooks-only"
		if withTracing {
			name = "full-tracing"
		}
		t.Run(name, func(t *testing.T) {
			skipIfNotRoot(t)

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

			tmpDir := t.TempDir()
			scriptPath := filepath.Join(tmpDir, "deep_nest.py")
			require.NoError(t, os.WriteFile(scriptPath, []byte(pythonScript), 0644))

			deepNestCmd := fmt.Sprintf("sh -c \"sh -c 'python3 %s'\"", scriptPath)

			cmd := newCmd(withTracing, []string{"sh", "-c", deepNestCmd})

			ctx, err := attestation.NewContext("test-deep-nesting-exec", []attestation.Attestor{cmd, networkAttestor})
			require.NoError(t, err)

			err = ctx.RunAttestors()
			require.NoError(t, err)
			assertNoAttestorErrors(t, ctx)

			connections := networkAttestor.NetworkTrace.Connections
			assert.Len(t, connections, 3, "Should intercept exactly 3 connections across the nested execve lifecycle")

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
		})
	}
}
func TestIntegrationCurlHTTPS(t *testing.T) {
	for _, withTracing := range []bool{false, true} {
		name := "hooks-only"
		if withTracing {
			name = "full-tracing"
		}
		t.Run(name, func(t *testing.T) {
			skipIfNotRoot(t)

			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("Hello HTTPS"))
			}))
			defer server.Close()

			serverURL, err := url.Parse(server.URL)
			require.NoError(t, err)
			_, portStr, err := net.SplitHostPort(serverURL.Host)
			require.NoError(t, err)
			serverPort, err := strconv.Atoi(portStr)
			require.NoError(t, err)

			config := types.Config{
				ObserveChildTree: true,
				ProxyPort:        testProxyPort + 6,
				ProxyBindIPv4:    "127.0.0.1",
				GenerateCA:       true,
				CACertPath:       types.DefaultCaCertPath,
				CAKeyPath:        types.DefaultCaKeyPath,
				SkipVerify:       true,
				Payload: types.PayloadConfig{
					RecordPayload:     true,
					RecordPayloadHash: true,
					MaxPayloadSize:    1024 * 1024,
				},
				EnableHTTPInspection: true,
			}

			networkAttestor := NewWithConfig(config)
			log.SetLogger(log.ConsoleLogger{})

			t.Cleanup(func() {
				os.RemoveAll(filepath.Dir(types.DefaultCaCertPath))
			})

			curlCmd := fmt.Sprintf(
				"curl -s --cacert %s --resolve localhost:%d:127.0.0.1 https://localhost:%d/",
				types.DefaultCaCertPath, serverPort, serverPort,
			)

			cmd := newCmd(withTracing, []string{"sh", "-c", curlCmd})

			ctx, err := attestation.NewContext("test-https", []attestation.Attestor{cmd, networkAttestor})
			require.NoError(t, err)

			err = ctx.RunAttestors()
			require.NoError(t, err)

			require.NotEmpty(t, networkAttestor.NetworkTrace.Connections, "Should record at least one connection")

			found := false
			for _, conn := range networkAttestor.NetworkTrace.Connections {
				if conn.Destination.Port == uint16(serverPort) {
					found = true
					assert.True(t, conn.Intercepted, "Connection should be marked as intercepted")

					responseFound := false

					for _, exchange := range conn.HTTPExchanges {
						if exchange.Response != nil &&
							string(exchange.Response.Body.Data) == "Hello HTTPS" {
							responseFound = true
							break
						}
					}

					if !responseFound {
						for _, pl := range conn.TCPPayloads {
							if string(pl.Payload.Data) == "Hello HTTPS" {
								responseFound = true
								break
							}
						}
					}

					assert.True(t, responseFound, "Should capture decrypted HTTPS response body")
					break
				}
			}
			assert.True(t, found, "Should find the connection to test server on port %d", serverPort)
		})
	}
}

// TestIntegrationRealWorldHTTPS downloads small metadata files from real package
// registries (PyPI, Go module proxy, Maven Central) through the transparent MITM
// proxy and verifies that connections are intercepted, decrypted, and recorded.
//
// This test requires:
//   - root privileges (BPF)
//   - internet access
//
// It is skipped automatically when either condition is not met.
func TestIntegrationRealWorldHTTPS(t *testing.T) {
	skipIfNotRoot(t)

	dialConn, err := net.DialTimeout("tcp", "pypi.org:443", 3*time.Second)
	if err != nil {
		t.Skip("Skipping test: no internet connectivity")
	}
	dialConn.Close()

	tests := []struct {
		name     string
		host     string
		url      string
		contains string
	}{
		{
			name:     "PyPI",
			host:     "pypi.org",
			url:      "https://pypi.org/pypi/pip/json",
			contains: "\"name\":\"pip\"",
		},
		{
			name:     "GoProxy",
			host:     "proxy.golang.org",
			url:      "https://proxy.golang.org/golang.org/x/text/@v/list",
			contains: "v0.",
		},
		{
			name:     "MavenCentral",
			host:     "repo1.maven.org",
			url:      "https://repo1.maven.org/maven2/junit/junit/maven-metadata.xml",
			contains: "<artifactId>junit</artifactId>",
		},
	}

	for _, withTracing := range []bool{false, true} {
		tracingName := "hooks-only"
		if withTracing {
			tracingName = "full-tracing"
		}
		t.Run(tracingName, func(t *testing.T) {
			for i, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					config := types.Config{
						ObserveChildTree: true,
						ProxyPort:        testProxyPort + 10 + uint16(i),
						ProxyBindIPv4:    "127.0.0.1",
						GenerateCA:       true,
						CACertPath:       types.DefaultCaCertPath,
						CAKeyPath:        types.DefaultCaKeyPath,
						SkipVerify:       false,
						Payload: types.PayloadConfig{
							RecordPayload:     true,
							RecordPayloadHash: true,
							MaxPayloadSize:    1024 * 1024,
						},
						EnableHTTPInspection: true,
					}

					networkAttestor := NewWithConfig(config)
					log.SetLogger(log.ConsoleLogger{})

					t.Cleanup(func() {
						os.RemoveAll(filepath.Dir(types.DefaultCaCertPath))
					})

					curlCmd := fmt.Sprintf(
						"curl -sS --cacert %s %s -o /dev/null -w '%%{http_code}'",
						types.DefaultCaCertPath, tt.url,
					)

					cmd := newCmd(withTracing, []string{"sh", "-c", curlCmd})

					ctx, err := attestation.NewContext(
						fmt.Sprintf("test-real-%s", tt.name),
						[]attestation.Attestor{cmd, networkAttestor},
					)
					require.NoError(t, err)

					err = ctx.RunAttestors()
					require.NoError(t, err)

					require.NotEmpty(t, networkAttestor.NetworkTrace.Connections,
						"Should record at least one connection")

					found := false
					for _, conn := range networkAttestor.NetworkTrace.Connections {
						if conn.Destination.Hostname != tt.host {
							continue
						}
						found = true

						assert.Equal(t, "https", conn.Protocol,
							"Connection to %s should be https", tt.host)

						assert.True(t, conn.Intercepted,
							"Connection to %s should be intercepted", tt.host)

						assert.Equal(t, uint16(443), conn.Destination.Port,
							"Connection to %s should target port 443", tt.host)

						if assert.NotNil(t, conn.TLS, "TLS info should be present for %s", tt.host) {
							if assert.NotNil(t, conn.TLS.ClientHello,
								"ClientHello should be recorded for %s", tt.host) {
								assert.NotEmpty(t, conn.TLS.ClientHello.SupportedVersions,
									"ClientHello should list TLS versions for %s", tt.host)
								assert.NotEmpty(t, conn.TLS.ClientHello.CipherSuites,
									"ClientHello should list cipher suites for %s", tt.host)
							}
						}

						require.NotEmpty(t, conn.HTTPExchanges,
							"Should have HTTP exchanges for %s", tt.host)

						exchange := conn.HTTPExchanges[0]

						assert.Equal(t, "GET", exchange.Request.Method,
							"Request method should be GET for %s", tt.host)
						assert.Contains(t, exchange.Request.URL, tt.host,
							"Request URL should contain %s", tt.host)

						if assert.NotNil(t, exchange.Response,
							"Response should be present for %s", tt.host) {
							assert.Equal(t, 200, exchange.Response.StatusCode,
								"Response status for %s should be 200", tt.host)
							assert.Greater(t, exchange.Response.Body.Size, int64(0),
								"Response body for %s should not be empty", tt.host)

							d := string(exchange.Response.Body.Data)
							assert.Contains(t, string(d), tt.contains,
								"Response body from %s should contain %q", tt.host, tt.contains)

							assert.NotEmpty(t, exchange.Response.Body.Hash,
								"Response body hash should be recorded for %s", tt.host)
						}

						assert.Greater(t, conn.BytesReceived, uint64(0),
							"Should have received bytes from %s", tt.host)

						break
					}

					assert.True(t, found,
						"Should find an intercepted connection to %s", tt.host)
				})
			}
		})
	}
}

func TestMain(m *testing.M) {
	log.SetLogger(log.ConsoleLogger{})

	// Ensure the working directory is the package source directory so that
	// testdata/ paths resolve correctly regardless of where go test was
	// invoked from.
	if _, filename, _, ok := runtime.Caller(0); ok {
		dir := filepath.Dir(filename)
		if err := os.Chdir(dir); err != nil {
			log.Errorf("failed to chdir to package dir %s: %v", dir, err)
		}
	}

	ec := m.Run()
	os.Exit(ec)
}

// ---------------------------------------------------------------------------
// C-based namespace tests
// ---------------------------------------------------------------------------

// compileCTest compiles a C source file from testdata/ into a temporary
// binary and returns its path. The test_helpers.h header in testdata/ is
// used via -I.
func compileCTest(t *testing.T, name string) string {
	t.Helper()
	testdataDir := "testdata"
	srcPath := filepath.Join(testdataDir, name+".c")
	binPath := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("gcc", "-o", binPath, srcPath,
		"-I"+testdataDir, "-Wall", "-Werror")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "compile %s: %s", name, string(out))
	return binPath
}

// findPayload searches recorded connections for a client_to_server payload
// matching want and returns true if found.
func findPayload(conns []types.Connection, want string) bool {
	for _, c := range conns {
		for _, p := range c.TCPPayloads {
			if p.Direction == "client_to_server" && string(p.Payload.Data) == want {
				return true
			}
		}
	}
	return false
}

// TestIntegrationCloneNewPidNewNet verifies the core docker case: a child
// created with CLONE_NEWPID | CLONE_NEWNET is frozen at execve, the sweep
// loop injects a proxy into the new netns via setns, marks it ready, and
func TestIntegrationCloneNewPidNewNet(t *testing.T) {
	skipIfNotRoot(t)

	bin := compileCTest(t, "t5_clone_newpid_newnet")

	for _, withTracing := range []bool{false, true} {
		name := "hooks-only"
		if withTracing {
			name = "full-tracing"
		}
		t.Run(name, func(t *testing.T) {
			const port = 19901
			server := newTestTCPServer(t, port, []byte("PONG"))
			defer server.wait()

			config := types.Config{
				ProxyPort:        testProxyPort + 20,
				ProxyBindIPv4:    "127.0.0.1",
				ObserveChildTree: true,
				Payload:          types.PayloadConfig{RecordPayload: true},
			}
			networkAttestor := NewWithConfig(config)

			cmd := newCmd(withTracing, []string{bin, strconv.Itoa(port)})

			ctx, err := attestation.NewContext("t5-clone-newpid-newnet",
				[]attestation.Attestor{cmd, networkAttestor})
			require.NoError(t, err)

			err = ctx.RunAttestors()
			require.NoError(t, err)
			assertNoAttestorErrors(t, ctx)

			conns := networkAttestor.NetworkTrace.Connections
			require.Len(t, conns, 1, "Should record one connection from the container netns")
			assert.True(t, findPayload(conns, "DOCKER"), "Should capture DOCKER payload")
		})
	}
}

func TestIntegrationDeepNestingLevels(t *testing.T) {
	skipIfNotRoot(t)

	bin := compileCTest(t, "t6_deep_nesting_levels")

	for _, withTracing := range []bool{false, true} {
		name := "hooks-only"
		if withTracing {
			name = "full-tracing"
		}
		t.Run(name, func(t *testing.T) {
			const port = 19902
			server := newTestTCPServer(t, port, []byte("PONG"))
			defer server.wait()

			config := types.Config{
				ProxyPort:        testProxyPort + 21,
				ProxyBindIPv4:    "127.0.0.1",
				ObserveChildTree: true,
				Payload:          types.PayloadConfig{RecordPayload: true},
			}
			networkAttestor := NewWithConfig(config)

			cmd := newCmd(withTracing, []string{bin, strconv.Itoa(port)})

			ctx, err := attestation.NewContext("t6-deep-nesting",
				[]attestation.Attestor{cmd, networkAttestor})
			require.NoError(t, err)

			err = ctx.RunAttestors()
			require.NoError(t, err)
			assertNoAttestorErrors(t, ctx)

			conns := networkAttestor.NetworkTrace.Connections
			require.Len(t, conns, 1, "Should record one connection from depth-3 container")
			assert.True(t, findPayload(conns, "DEEP"), "Should capture DEEP payload")
		})
	}
}

func TestIntegrationPidNsCleanup(t *testing.T) {
	skipIfNotRoot(t)

	bin := compileCTest(t, "t7_pid_ns_cleanup")

	for _, withTracing := range []bool{false, true} {
		name := "hooks-only"
		if withTracing {
			name = "full-tracing"
		}
		t.Run(name, func(t *testing.T) {
			const port = 19903
			server := newMultiConnTCPServer(t, port, []byte("PONG"), 2)
			defer server.wait()

			config := types.Config{
				ProxyPort:        testProxyPort + 22,
				ProxyBindIPv4:    "127.0.0.1",
				ObserveChildTree: true,
				Payload:          types.PayloadConfig{RecordPayload: true},
			}
			networkAttestor := NewWithConfig(config)

			cmd := newCmd(withTracing, []string{bin, strconv.Itoa(port)})

			ctx, err := attestation.NewContext("t7-pidns-cleanup",
				[]attestation.Attestor{cmd, networkAttestor})
			require.NoError(t, err)

			err = ctx.RunAttestors()
			require.NoError(t, err)
			assertNoAttestorErrors(t, ctx)

			conns := networkAttestor.NetworkTrace.Connections
			assert.Len(t, conns, 2, "Should record two connections (one per container)")
			for _, c := range conns {
				assert.True(t, findPayload([]types.Connection{c}, "CLEANUP"),
					"Each container should have sent CLEANUP")
				assert.True(t, c.Process.PID == 1, "Both should be in a separate namespace with PID 1")
			}
		})
	}
}

func TestIntegrationUntrackedSibling(t *testing.T) {
	skipIfNotRoot(t)

	bin := compileCTest(t, "t5_clone_newpid_newnet")

	for _, withTracing := range []bool{false, true} {
		name := "hooks-only"
		if withTracing {
			name = "full-tracing"
		}
		t.Run(name, func(t *testing.T) {
			const port = 19904
			server := newTestTCPServer(t, port, []byte("PONG"))

			config := types.Config{
				ProxyPort:        testProxyPort + 23,
				ProxyBindIPv4:    "127.0.0.1",
				ObserveChildTree: false,
				Payload:          types.PayloadConfig{RecordPayload: true},
			}
			networkAttestor := NewWithConfig(config)

			cmd := newCmd(withTracing, []string{bin, strconv.Itoa(port)})

			ctx, err := attestation.NewContext("t9-untracked-sibling",
				[]attestation.Attestor{cmd, networkAttestor})
			require.NoError(t, err)

			err = ctx.RunAttestors()
			require.NoError(t, err)
			assertNoAttestorErrors(t, ctx)

			conns := networkAttestor.NetworkTrace.Connections
			assert.Empty(t, conns, "Should NOT record any connections from untracked sibling")

			_ = server.listener.Close()
			server.wait()
		})
	}
}

// newMultiConnTCPServer is like newTestTCPServer but accepts up to n
// sequential connections.
func newMultiConnTCPServer(t *testing.T, port int, response []byte, n int) *testTCPServer {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(t, err)

	server := &testTCPServer{
		listener:     listener,
		port:         port,
		response:     response,
		receivedData: make(chan []byte, n),
		done:         make(chan struct{}),
	}

	go func() {
		defer close(server.done)
		defer listener.Close()
		for i := 0; i < n; i++ {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				data, err := io.ReadAll(conn)
				if err != nil {
					server.receivedData <- nil
					return
				}
				server.receivedData <- data
				if len(response) > 0 {
					_, _ = conn.Write(response)
				}
			}()
		}
	}()
	return server
}
