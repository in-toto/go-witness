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
	"fmt"
	"time"

	"github.com/in-toto/go-witness/attestation/networktrace/bpf"
	"github.com/in-toto/go-witness/attestation/networktrace/types"
)

// Direction indicates data flow direction
type Direction int

const (
	DirectionClientToServer Direction = iota
	DirectionServerToClient
)

func (d Direction) String() string {
	if d == DirectionClientToServer {
		return "client_to_server"
	}
	return "server_to_client"
}

// ConnectionRecorder records traffic for a single connection
// Each connection gets its own recorder - no sharing, no locks needed
type ConnectionRecorder struct {
	config types.PayloadConfig
	conn   types.Connection
}

// NewConnectionRecorder creates a recorder for a single connection
func NewConnectionRecorder(metadata *bpf.ConnectionMetadata, protocol string, config types.PayloadConfig) *ConnectionRecorder {
	return &ConnectionRecorder{
		config: config,
		conn: types.Connection{
			ID:        fmt.Sprintf("%d-%d", metadata.SockCookie, time.Now().UnixNano()),
			Protocol:  protocol,
			StartTime: time.Now(),
			Process: types.ProcessInfo{
				PID:      metadata.PID,
				Comm:     metadata.Comm,
				CgroupID: metadata.CgroupID,
			},
			Destination: types.Endpoint{
				IP:   metadata.OrigIP,
				Port: metadata.OrigPort,
			},
		},
	}
}

// RecordTCPPayloadDirect records raw TCP data without copying
// Takes ownership of the data slice - caller must not modify after calling
// Records even empty payloads to capture zero-byte connections (important for security attestation)
func (r *ConnectionRecorder) RecordTCPPayloadDirect(direction Direction, data []byte) {
	r.conn.TCPPayloads = append(r.conn.TCPPayloads, types.TCPPayload{
		Timestamp: time.Now(),
		Direction: direction.String(),
		Payload:   types.NewPayload(data, r.config),
	})

	if direction == DirectionClientToServer {
		r.conn.BytesSent += uint64(len(data))
	} else {
		r.conn.BytesReceived += uint64(len(data))
	}
}

// SetProtocol updates the connection protocol
func (r *ConnectionRecorder) SetProtocol(protocol string) {
	r.conn.Protocol = protocol
}

// SetError records an error on the connection
func (r *ConnectionRecorder) SetError(err error) {
	if err != nil {
		r.conn.Error = err.Error()
	}
}

// Finish marks the connection as ended and returns the recorded connection
func (r *ConnectionRecorder) Finish() types.Connection {
	endTime := time.Now()
	r.conn.EndTime = endTime
	return r.conn
}
