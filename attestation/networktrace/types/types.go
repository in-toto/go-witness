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

package types

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"time"
)

// PayloadConfig controls how payloads are recorded
type PayloadConfig struct {
	// RecordPayload enables storing raw payload data (default: false)
	RecordPayload bool `json:"record_payload"`
	// RecordPayloadHash enables storing SHA256 hash of payload (default: true)
	RecordPayloadHash bool `json:"record_payload_hash"`
	// MaxPayloadSize is the maximum size in bytes to store raw payload
	// If payload exceeds this, it will be truncated
	// Set to 0 for unlimited (default: 1MB)
	MaxPayloadSize int64 `json:"max_payload_size"`
}

// DefaultPayloadConfig returns sensible defaults for payload recording
func DefaultPayloadConfig() PayloadConfig {
	return PayloadConfig{
		RecordPayload:     false,
		RecordPayloadHash: true,
		MaxPayloadSize:    1024 * 1024, // 1MB
	}
}

// ProcessInfo identifies the process that made the connection
type ProcessInfo struct {
	PID      uint32 `json:"pid"`
	Comm     string `json:"comm"`
	CgroupID uint64 `json:"cgroup_id,omitempty"`
}

// Endpoint represents a network endpoint (source or destination)
type Endpoint struct {
	IP       net.IP `json:"ip"`
	Port     uint16 `json:"port"`
	Hostname string `json:"hostname,omitempty"` // From SNI or Host header
}

// Payload represents recorded data with configurable storage options
type Payload struct {
	// Size is always recorded (bytes)
	Size int64 `json:"size"`
	// Data contains the raw payload (if RecordPayload=true and size <= MaxPayloadSize)
	Data []byte `json:"data,omitempty"`
	// Hash contains SHA256 hash of payload (if RecordPayloadHash=true)
	Hash string `json:"hash,omitempty"`
	// Truncated indicates Data was omitted due to size limits (hash still present if enabled)
	Truncated bool `json:"truncated,omitempty"`
}

// NewPayload creates a Payload based on configuration
// After calling this function, user should not use the data slice anymore
// The ownership of data is transferred to the Payload struct
func NewPayload(data []byte, config PayloadConfig) Payload {
	p := Payload{
		Size: int64(len(data)),
	}

	if len(data) == 0 {
		return p
	}

	// Calculate and store hash if enabled
	if config.RecordPayloadHash {
		hash := sha256.Sum256(data)
		p.Hash = hex.EncodeToString(hash[:])
	}

	// Store raw payload if enabled and within size limits
	if config.RecordPayload {
		if config.MaxPayloadSize == 0 || int64(len(data)) <= config.MaxPayloadSize {
			p.Data = data
		} else {
			// Payload exceeds max size, mark as truncated
			p.Truncated = true
			// Store only up to MaxPayloadSize
			p.Data = data[:config.MaxPayloadSize]
		}
	}

	return p
}

// TCPPayload represents raw TCP payload for non-HTTP connections
type TCPPayload struct {
	Timestamp time.Time `json:"timestamp"`
	Direction string    `json:"direction"` // "client_to_server" or "server_to_client"
	Payload   Payload   `json:"payload"`
}

// Connection represents a single network connection
type Connection struct {
	// Unique identifier (socket cookie from eBPF)
	ID string `json:"id"`

	// Protocol: "tcp", "http", "https"
	Protocol string `json:"protocol"`

	// Timing
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time,omitempty"`

	// Process that initiated the connection
	Process ProcessInfo `json:"process"`

	// Network endpoints
	// TODO: Update bpf maps to store source endpoint as well
	// Source      Endpoint `json:"source"`
	Destination Endpoint `json:"destination"`

	// Raw TCP payloads
	TCPPayloads []TCPPayload `json:"tcp_payloads,omitempty"`

	// Traffic statistics
	BytesSent     uint64 `json:"bytes_sent"`
	BytesReceived uint64 `json:"bytes_received"`

	Error string `json:"error,omitempty"`
}

// NetworkSummary provides aggregated statistics for quick policy evaluation
type NetworkSummary struct {
	TotalConnections   int            `json:"total_connections"`
	ProtocolCounts     map[string]int `json:"protocol_counts"`
	UniqueHosts        []string       `json:"unique_hosts"`
	UniqueIPs          []string       `json:"unique_ips"`
	TotalBytesSent     uint64         `json:"total_bytes_sent"`
	TotalBytesReceived uint64         `json:"total_bytes_received"`
}

// ComputeSummary calculates a NetworkSummary from a slice of Connections
func ComputeSummary(connections []Connection) NetworkSummary {
	summary := NetworkSummary{
		TotalConnections: len(connections),
		ProtocolCounts:   make(map[string]int),
	}

	hostSet := make(map[string]struct{})
	ipSet := make(map[string]struct{})

	for _, conn := range connections {
		// Count protocols
		summary.ProtocolCounts[conn.Protocol]++

		// Aggregate bytes
		summary.TotalBytesSent += conn.BytesSent
		summary.TotalBytesReceived += conn.BytesReceived

		// Collect unique hosts
		if conn.Destination.Hostname != "" {
			hostSet[conn.Destination.Hostname] = struct{}{}
		}
		if conn.Destination.IP != nil {
			ipSet[conn.Destination.IP.String()] = struct{}{}
		}
	}

	for host := range hostSet {
		summary.UniqueHosts = append(summary.UniqueHosts, host)
	}
	for ip := range ipSet {
		summary.UniqueIPs = append(summary.UniqueIPs, ip)
	}

	return summary
}
