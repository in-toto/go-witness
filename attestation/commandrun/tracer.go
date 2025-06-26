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

package commandrun

import (
	"os/exec"
	"time"

	"github.com/in-toto/go-witness/attestation"
)

// TracerOptions configures the behavior of the process tracer
type TracerOptions struct {
	// EnableHashing controls whether file and program digests are calculated
	// This can be disabled for performance-sensitive applications
	EnableHashing bool

	// EnableNetworkTrace controls whether network syscalls are traced
	// This adds overhead but provides visibility into network operations
	EnableNetworkTrace bool
}

// Tracer is the interface for platform-specific process tracing implementations
type Tracer interface {
	// Start begins tracing the provided command
	Start(cmd *exec.Cmd) error

	// Wait waits for the command to complete and returns any error
	Wait() error

	// GetProcessTree returns the complete process tree from the traced execution
	GetProcessTree() []ProcessInfo
	
	// GetStartTime returns when tracing started
	GetStartTime() *time.Time
	
	// GetEndTime returns when tracing ended
	GetEndTime() *time.Time
}

// NewTracer creates a platform-specific tracer implementation
func NewTracer(ctx *attestation.AttestationContext, opts TracerOptions) Tracer {
	return newPlatformTracer(ctx, opts)
}