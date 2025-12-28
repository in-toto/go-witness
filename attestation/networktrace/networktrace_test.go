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
	"testing"
	"time"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/commandrun"
	"github.com/in-toto/go-witness/attestation/networktrace/types"
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

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	data, err := io.ReadAll(conn)
	if err != nil {
		s.receivedData <- nil
		return
	}
	s.receivedData <- data

	if len(s.response) > 0 {
		conn.Write(s.response)
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
		commandrun.WithSilent(true),
	)

	ctx, err := attestation.NewContext("test-networktrace", []attestation.Attestor{cmd, networkAttestor})
	require.NoError(t, err)

	err = ctx.RunAttestors()
	require.NoError(t, err)

	receivedData := <-server.receivedData
	assert.Equal(t, []byte(clientRequest), receivedData, "Server should receive exact request data")

	assert.False(t, networkAttestor.attestation.StartTime.IsZero())
	assert.False(t, networkAttestor.attestation.EndTime.IsZero())
	assert.True(t, networkAttestor.attestation.EndTime.After(networkAttestor.attestation.StartTime))

	// Realistically the server should see only one connection
	assert.Len(t, networkAttestor.attestation.Connections, 1, "Should record one connection")

	conn := networkAttestor.attestation.Connections[0]
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
		commandrun.WithSilent(true),
	)

	ctx, err := attestation.NewContext("test-zero", []attestation.Attestor{cmd, networkAttestor})
	require.NoError(t, err)

	err = ctx.RunAttestors()
	require.NoError(t, err)

	receivedData := <-server.receivedData
	assert.Equal(t, []byte{}, receivedData, "Server should receive zero-byte data")

	assert.Len(t, networkAttestor.attestation.Connections, 1, "Should record one connection")
	conn := networkAttestor.attestation.Connections[0]
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
