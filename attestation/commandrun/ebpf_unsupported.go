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

//go:build !linux

package commandrun

import (
	"errors"
	"os/exec"

	"github.com/in-toto/go-witness/attestation"
)

func (rc *CommandRun) usesEBPFTracing() bool {
	return rc.traceBackend == TraceBackendEBPF
}

func (rc *CommandRun) traceWithEBPF(c *exec.Cmd, actx *attestation.AttestationContext, hasPreExec, hasPreExit bool) ([]ProcessInfo, error) {
	return nil, errors.New("eBPF tracing not supported on this platform")
}
