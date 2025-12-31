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

const (
	DefaultProxyPort     = 8888
	DefaultProxyBindIPv4 = "127.0.0.1"
)

// Config controls the network trace attestor behavior
type Config struct {
	// Observation targets - which processes to monitor
	ObservePIDs      []uint32 `json:"observe_pids,omitempty"`
	ObserveCgroups   []string `json:"observe_cgroups,omitempty"`
	ObserveCommands  []string `json:"observe_commands,omitempty"`
	ObserveChildTree bool     `json:"observe_child_tree"`

	// Proxy configuration
	ProxyPort     uint16 `json:"proxy_port"`
	ProxyBindIPv4 string `json:"proxy_bind_ipv4"`

	// Payload recording options
	Payload PayloadConfig `json:"payload"`
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() Config {
	return Config{
		ProxyPort:        DefaultProxyPort,
		ProxyBindIPv4:    DefaultProxyBindIPv4,
		ObserveChildTree: true,
		Payload:          DefaultPayloadConfig(),
	}
}
