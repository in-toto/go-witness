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
	"strconv"
	"testing"
	"time"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/commandrun"
	"github.com/in-toto/go-witness/attestation/networktrace/types"
	"github.com/in-toto/go-witness/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		EnableHTTPInspection: false,
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
		EnableHTTPInspection: false,
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
		EnableHTTPInspection: false,
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
	case <-time.After(10 * time.Second):
		t.Fatal("DEADLOCK DETECTED: Test timed out! The proxy failed to forcefully close lingering connections during shutdown, causing io.Copy to block forever.")
	}
}

func TestIntegrationCurlHTTPS(t *testing.T) {
	skipIfNotRoot(t)

	// Start a test HTTPS server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello HTTPS"))
	}))
	defer server.Close()

	// Parse server port
	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	_, portStr, err := net.SplitHostPort(serverURL.Host)
	require.NoError(t, err)
	serverPort, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	config := types.Config{
		ObserveChildTree: true,
		ProxyPort:        testProxyPort + 2,
		ProxyBindIPv4:    "127.0.0.1",
		GenerateCA:       true,
		CACertPath:       types.DefaultCaCertPath,
		CAKeyPath:        types.DefaultCaKeyPath,
		SkipVerify:       true, // Skip verifying upstream (httptest) cert
		Payload: types.PayloadConfig{
			RecordPayload:     true,
			RecordPayloadHash: true,
			MaxPayloadSize:    1024 * 1024,
		},
		EnableHTTPInspection: true,
	}

	networkAttestor := NewWithConfig(config)
	log.SetLogger(log.ConsoleLogger{})

	// Use --resolve so curl connects to "localhost" (which sends SNI in the TLS
	// ClientHello) while actually hitting 127.0.0.1:<port>.  The proxy's MITM
	// cert will be generated for "localhost" thanks to the SNI.
	// --cacert trusts the proxy CA for the MITM cert.
	curlCmd := fmt.Sprintf(
		"curl -s --cacert %s --resolve localhost:%d:127.0.0.1 https://localhost:%d/",
		types.DefaultCaCertPath, serverPort, serverPort,
	)

	cmd := commandrun.New(
		commandrun.WithCommand([]string{"sh", "-c", curlCmd}),
		commandrun.WithSilent(false),
	)

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

			// For HTTPS connections going through the HTTP proxy, the response
			// body is captured in HTTPExchanges, not in TCPPayloads.
			responseFound := false

			// Check HTTPExchanges (populated by the HTTP proxy MITM path)
			for _, exchange := range conn.HTTPExchanges {
				if exchange.Response != nil &&
					string(exchange.Response.Body.Data) == "Hello HTTPS" {
					responseFound = true
					break
				}
			}

			// Also check TCPPayloads as fallback
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

	// Quick connectivity check — skip if we can't reach the internet
	dialConn, err := net.DialTimeout("tcp", "pypi.org:443", 3*time.Second)
	if err != nil {
		t.Skip("Skipping test: no internet connectivity")
	}
	dialConn.Close()

	// Each sub-test downloads a small JSON/XML metadata file from a real registry.
	tests := []struct {
		name     string
		host     string // hostname for SNI and assertions
		url      string // full URL to fetch
		contains string // substring expected in the response body
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

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := types.Config{
				ObserveChildTree: true,
				ProxyPort:        testProxyPort + 10 + uint16(i),
				ProxyBindIPv4:    "127.0.0.1",
				GenerateCA:       true,
				CACertPath:       types.DefaultCaCertPath,
				CAKeyPath:        types.DefaultCaKeyPath,
				SkipVerify:       false, // real certs — no need to skip
				Payload: types.PayloadConfig{
					RecordPayload:     true,
					RecordPayloadHash: true,
					MaxPayloadSize:    1024 * 1024,
				},
				EnableHTTPInspection: true,
			}

			networkAttestor := NewWithConfig(config)
			log.SetLogger(log.ConsoleLogger{})

			curlCmd := fmt.Sprintf(
				"curl -sS --cacert %s %s -o /dev/null -w '%%{http_code}'",
				types.DefaultCaCertPath, tt.url,
			)

			cmd := commandrun.New(
				commandrun.WithCommand([]string{"sh", "-c", curlCmd}),
				commandrun.WithSilent(false),
			)

			ctx, err := attestation.NewContext(
				fmt.Sprintf("test-real-%s", tt.name),
				[]attestation.Attestor{cmd, networkAttestor},
			)
			require.NoError(t, err)

			err = ctx.RunAttestors()
			require.NoError(t, err)

			require.NotEmpty(t, networkAttestor.NetworkTrace.Connections,
				"Should record at least one connection")

			// Find the connection to the expected host
			found := false
			for _, conn := range networkAttestor.NetworkTrace.Connections {
				if conn.Destination.Hostname != tt.host {
					continue
				}
				found = true

				// Protocol should be https (intercepted via MITM)
				assert.Equal(t, "https", conn.Protocol,
					"Connection to %s should be https", tt.host)

				// Must be intercepted
				assert.True(t, conn.Intercepted,
					"Connection to %s should be intercepted", tt.host)

				// Destination port should be 443
				assert.Equal(t, uint16(443), conn.Destination.Port,
					"Connection to %s should target port 443", tt.host)

				// TLS info should be present with ClientHello details
				if assert.NotNil(t, conn.TLS, "TLS info should be present for %s", tt.host) {
					if assert.NotNil(t, conn.TLS.ClientHello,
						"ClientHello should be recorded for %s", tt.host) {
						assert.NotEmpty(t, conn.TLS.ClientHello.SupportedVersions,
							"ClientHello should list TLS versions for %s", tt.host)
						assert.NotEmpty(t, conn.TLS.ClientHello.CipherSuites,
							"ClientHello should list cipher suites for %s", tt.host)
					}
				}

				// HTTP exchanges should be recorded
				require.NotEmpty(t, conn.HTTPExchanges,
					"Should have HTTP exchanges for %s", tt.host)

				exchange := conn.HTTPExchanges[0]

				// Request
				assert.Equal(t, "GET", exchange.Request.Method,
					"Request method should be GET for %s", tt.host)
				assert.Contains(t, exchange.Request.URL, tt.host,
					"Request URL should contain %s", tt.host)

				// Response
				if assert.NotNil(t, exchange.Response,
					"Response should be present for %s", tt.host) {
					assert.Equal(t, 200, exchange.Response.StatusCode,
						"Response status for %s should be 200", tt.host)
					assert.Greater(t, exchange.Response.Body.Size, int64(0),
						"Response body for %s should not be empty", tt.host)

					d := string(exchange.Response.Body.Data)
					assert.Contains(t, string(d), tt.contains,
						"Response body from %s should contain %q", tt.host, tt.contains)

					// Payload hash should be recorded
					assert.NotEmpty(t, exchange.Response.Body.Hash,
						"Response body hash should be recorded for %s", tt.host)
				}

				// Bytes received should be > 0
				assert.Greater(t, conn.BytesReceived, uint64(0),
					"Should have received bytes from %s", tt.host)

				break
			}

			assert.True(t, found,
				"Should find an intercepted connection to %s", tt.host)
		})
	}
}

func TestMain(m *testing.M) {
	log.SetLogger(log.ConsoleLogger{})
	ec := m.Run()
	os.Exit(ec)
}
