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

package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"testing"

	"github.com/in-toto/go-witness/attestation/networktrace/bpf"
	"github.com/in-toto/go-witness/attestation/networktrace/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConnectionRecorder(t *testing.T) {
	metadata := &bpf.ConnectionMetadata{
		SockCookie: 12345,
		PID:        1000,
		CgroupID:   100,
		Comm:       "test-process",
		OrigIP:     net.ParseIP("192.168.1.1"),
		OrigPort:   443,
	}

	payloadConfig := types.PayloadConfig{
		RecordPayload:     true,
		RecordPayloadHash: true,
		MaxPayloadSize:    1024 * 1024,
	}

	recorder := NewConnectionRecorder(metadata, "tcp", payloadConfig)

	require.NotNil(t, recorder)
	assert.Equal(t, payloadConfig, recorder.config)
	assert.Equal(t, "tcp", recorder.conn.Protocol)
	assert.Equal(t, uint32(1000), recorder.conn.Process.PID)
	assert.Equal(t, "test-process", recorder.conn.Process.Comm)
	assert.Equal(t, uint64(100), recorder.conn.Process.CgroupID)
	assert.True(t, recorder.conn.Destination.IP.Equal(net.ParseIP("192.168.1.1")))
	assert.Equal(t, uint16(443), recorder.conn.Destination.Port)
	assert.NotEmpty(t, recorder.conn.ID)
	assert.False(t, recorder.conn.StartTime.IsZero())
}

func TestRecordTCPPayloadDirect(t *testing.T) {
	metadata := &bpf.ConnectionMetadata{
		SockCookie: 12345,
		PID:        1000,
		Comm:       "test",
		OrigIP:     net.ParseIP("192.168.1.1"),
		OrigPort:   80,
	}

	payloadConfig := types.PayloadConfig{
		RecordPayload:     true,
		RecordPayloadHash: true,
		MaxPayloadSize:    1024 * 1024,
	}

	recorder := NewConnectionRecorder(metadata, "tcp", payloadConfig)

	clientData := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	serverData := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

	recorder.RecordTCPPayloadDirect(DirectionClientToServer, clientData)
	recorder.RecordTCPPayloadDirect(DirectionServerToClient, serverData)

	conn := recorder.Finish()

	assert.Len(t, conn.TCPPayloads, 2)
	assert.Equal(t, uint64(len(clientData)), conn.BytesSent)
	assert.Equal(t, uint64(len(serverData)), conn.BytesReceived)

	// Verify directions
	assert.Equal(t, "client_to_server", conn.TCPPayloads[0].Direction)
	assert.Equal(t, "server_to_client", conn.TCPPayloads[1].Direction)

	// Verify payload data is recorded
	assert.Equal(t, int64(len(clientData)), conn.TCPPayloads[0].Payload.Size)
	assert.Equal(t, int64(len(serverData)), conn.TCPPayloads[1].Payload.Size)
}

func TestRecordTCPPayloadDirectEmpty(t *testing.T) {
	// Empty payloads should still be recorded for security attestation
	// (e.g., zero-byte connections could indicate port probing/reconnaissance)
	metadata := &bpf.ConnectionMetadata{
		SockCookie: 12345,
		PID:        1000,
		Comm:       "test",
		OrigIP:     net.ParseIP("192.168.1.1"),
		OrigPort:   80,
	}

	payloadConfig := types.DefaultPayloadConfig()
	recorder := NewConnectionRecorder(metadata, "tcp", payloadConfig)

	// Record empty data - should still create payload entries
	recorder.RecordTCPPayloadDirect(DirectionClientToServer, []byte{})
	recorder.RecordTCPPayloadDirect(DirectionServerToClient, nil)

	conn := recorder.Finish()

	// Both directions should be recorded even with empty data
	assert.Len(t, conn.TCPPayloads, 2)
	assert.Equal(t, uint64(0), conn.BytesSent)
	assert.Equal(t, uint64(0), conn.BytesReceived)

	// Verify payloads have Size: 0
	assert.Equal(t, int64(0), conn.TCPPayloads[0].Payload.Size)
	assert.Equal(t, int64(0), conn.TCPPayloads[1].Payload.Size)
}

func TestSetProtocol(t *testing.T) {
	metadata := &bpf.ConnectionMetadata{
		SockCookie: 12345,
		PID:        1000,
		Comm:       "test",
		OrigIP:     net.ParseIP("192.168.1.1"),
		OrigPort:   443,
	}

	payloadConfig := types.DefaultPayloadConfig()
	recorder := NewConnectionRecorder(metadata, "tcp", payloadConfig)

	recorder.SetProtocol("https")
	conn := recorder.Finish()

	assert.Equal(t, "https", conn.Protocol)
}

func TestSetError(t *testing.T) {
	metadata := &bpf.ConnectionMetadata{
		SockCookie: 12345,
		PID:        1000,
		Comm:       "test",
		OrigIP:     net.ParseIP("192.168.1.1"),
		OrigPort:   80,
	}

	payloadConfig := types.DefaultPayloadConfig()
	recorder := NewConnectionRecorder(metadata, "tcp", payloadConfig)

	recorder.SetError(io.EOF)
	conn := recorder.Finish()

	assert.Equal(t, "EOF", conn.Error)
}

func TestSetErrorNil(t *testing.T) {
	metadata := &bpf.ConnectionMetadata{
		SockCookie: 12345,
		PID:        1000,
		Comm:       "test",
		OrigIP:     net.ParseIP("192.168.1.1"),
		OrigPort:   80,
	}

	payloadConfig := types.DefaultPayloadConfig()
	recorder := NewConnectionRecorder(metadata, "tcp", payloadConfig)

	recorder.SetError(nil)
	conn := recorder.Finish()

	assert.Empty(t, conn.Error)
}

func TestFinish(t *testing.T) {
	metadata := &bpf.ConnectionMetadata{
		SockCookie: 12345,
		PID:        1000,
		Comm:       "test",
		OrigIP:     net.ParseIP("192.168.1.1"),
		OrigPort:   80,
	}

	payloadConfig := types.DefaultPayloadConfig()
	recorder := NewConnectionRecorder(metadata, "tcp", payloadConfig)

	conn := recorder.Finish()

	assert.NotEmpty(t, conn.ID)
	assert.False(t, conn.StartTime.IsZero())
	assert.False(t, conn.EndTime.IsZero())
	assert.True(t, conn.EndTime.After(conn.StartTime) || conn.EndTime.Equal(conn.StartTime))
}

func TestDirectionString(t *testing.T) {
	assert.Equal(t, "client_to_server", DirectionClientToServer.String())
	assert.Equal(t, "server_to_client", DirectionServerToClient.String())
}

func TestConnectionIDFormat(t *testing.T) {
	metadata := &bpf.ConnectionMetadata{
		SockCookie: 12345,
		PID:        1000,
		Comm:       "test",
		OrigIP:     net.ParseIP("192.168.1.1"),
		OrigPort:   80,
	}

	payloadConfig := types.DefaultPayloadConfig()
	recorder := NewConnectionRecorder(metadata, "tcp", payloadConfig)

	conn := recorder.Finish()

	// ID should start with socket cookie
	assert.Contains(t, conn.ID, "12345-")
}

func TestIPv6Metadata(t *testing.T) {
	metadata := &bpf.ConnectionMetadata{
		SockCookie: 12345,
		PID:        1000,
		Comm:       "test",
		OrigIP:     net.ParseIP("::1"),
		OrigPort:   80,
	}

	payloadConfig := types.DefaultPayloadConfig()
	recorder := NewConnectionRecorder(metadata, "tcp", payloadConfig)
	conn := recorder.Finish()

	assert.True(t, conn.Destination.IP.Equal(net.ParseIP("::1")))
}

func TestPayloadConfigRecordBoth(t *testing.T) {
	metadata := &bpf.ConnectionMetadata{
		SockCookie: 12345,
		PID:        1000,
		Comm:       "test",
		OrigIP:     net.ParseIP("192.168.1.1"),
		OrigPort:   80,
	}

	payloadConfig := types.PayloadConfig{
		RecordPayload:     true,
		RecordPayloadHash: true,
		MaxPayloadSize:    1024,
	}

	recorder := NewConnectionRecorder(metadata, "tcp", payloadConfig)
	testData := []byte("test data")
	recorder.RecordTCPPayloadDirect(DirectionClientToServer, testData)

	conn := recorder.Finish()

	require.Len(t, conn.TCPPayloads, 1)
	assert.Equal(t, testData, conn.TCPPayloads[0].Payload.Data)

	// Calculate expected hash
	expectedHash := sha256.Sum256(testData)
	expectedHashHex := hex.EncodeToString(expectedHash[:])
	assert.Equal(t, expectedHashHex, conn.TCPPayloads[0].Payload.Hash)
}

func TestPayloadConfigHashOnly(t *testing.T) {
	metadata := &bpf.ConnectionMetadata{
		SockCookie: 12345,
		PID:        1000,
		Comm:       "test",
		OrigIP:     net.ParseIP("192.168.1.1"),
		OrigPort:   80,
	}

	payloadConfig := types.PayloadConfig{
		RecordPayload:     false,
		RecordPayloadHash: true,
		MaxPayloadSize:    1024,
	}

	testData := []byte("test data")
	recorder := NewConnectionRecorder(metadata, "tcp", payloadConfig)
	recorder.RecordTCPPayloadDirect(DirectionClientToServer, testData)

	conn := recorder.Finish()

	require.Len(t, conn.TCPPayloads, 1)
	assert.Empty(t, conn.TCPPayloads[0].Payload.Data)

	// Calculate expected hash
	expectedHash := sha256.Sum256(testData)
	expectedHashHex := hex.EncodeToString(expectedHash[:])
	assert.Equal(t, expectedHashHex, conn.TCPPayloads[0].Payload.Hash)
}

func TestPayloadConfigTruncation(t *testing.T) {
	metadata := &bpf.ConnectionMetadata{
		SockCookie: 12345,
		PID:        1000,
		Comm:       "test",
		OrigIP:     net.ParseIP("192.168.1.1"),
		OrigPort:   80,
	}

	payloadConfig := types.PayloadConfig{
		RecordPayload:     true,
		RecordPayloadHash: true,
		MaxPayloadSize:    5,
	}

	recorder := NewConnectionRecorder(metadata, "tcp", payloadConfig)
	fullData := []byte("test data longer than max")
	recorder.RecordTCPPayloadDirect(DirectionClientToServer, fullData)

	conn := recorder.Finish()

	require.Len(t, conn.TCPPayloads, 1)
	assert.True(t, conn.TCPPayloads[0].Payload.Truncated)
	assert.Equal(t, fullData[:5], conn.TCPPayloads[0].Payload.Data) // First 5 bytes
	assert.Equal(t, int64(len(fullData)), conn.TCPPayloads[0].Payload.Size)

	// Hash should be of the FULL data, not truncated
	expectedHash := sha256.Sum256(fullData)
	expectedHashHex := hex.EncodeToString(expectedHash[:])
	assert.Equal(t, expectedHashHex, conn.TCPPayloads[0].Payload.Hash)
}
