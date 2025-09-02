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
	"time"
	
	"github.com/in-toto/go-witness/attestation"
	"github.com/invopop/jsonschema"
)

const (
	TraceName = "command-run-trace"
	TraceType = "https://witness.dev/attestations/command-run-trace/v0.1"
)

func init() {
	attestation.RegisterAttestation(TraceName, TraceType, attestation.PostProductRunType, func() attestation.Attestor {
		return &TraceAttestation{}
	})
}

// TraceAttestation contains the complete process tree from a command execution
type TraceAttestation struct {
	// Processes contains all processes spawned during command execution
	// ordered by creation time, maintaining parent-child relationships
	Processes []ProcessInfo `json:"processes"`
	
	// EntryPoint is the process ID of the main command that was executed
	EntryPoint int `json:"entrypoint"`
	
	// TracingOptions records what tracing features were enabled
	TracingOptions TracerOptions `json:"tracingoptions"`
	
	// Platform information
	Platform string `json:"platform"` // linux, darwin, windows
	
	// Overall execution time
	StartTime *time.Time `json:"starttime,omitempty"`
	EndTime   *time.Time `json:"endtime,omitempty"`
}

func (ta *TraceAttestation) Name() string {
	return TraceName
}

func (ta *TraceAttestation) Type() string {
	return TraceType
}

func (ta *TraceAttestation) RunType() attestation.RunType {
	return attestation.PostProductRunType
}

func (ta *TraceAttestation) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(ta)
}

func (ta *TraceAttestation) Attest(ctx *attestation.AttestationContext) error {
	// TraceAttestation is populated by CommandRun, not through Attest
	return nil
}