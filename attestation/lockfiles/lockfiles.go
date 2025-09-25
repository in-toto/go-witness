// Copyright 2024 The Witness Contributors
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

package lockfiles

import (
	"crypto"
	"fmt"
	"os"
	"path/filepath"

	"github.com/invopop/jsonschema"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
)

const (
	Name    = "lockfiles"
	Type    = "https://witness.dev/attestations/lockfiles/v0.1"
	RunType = attestation.PreMaterialRunType
)

var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return NewLockfilesAttestor()
	})
}

func NewLockfilesAttestor() attestation.Attestor {
	return &Attestor{
		Lockfiles: []LockfileInfo{},
	}
}

// Attestor implements the lockfiles attestation type
type Attestor struct {
	Lockfiles []LockfileInfo `json:"lockfiles" jsonschema:"title=Lockfiles,description=List of discovered dependency lockfiles"`
}

// LockfileInfo stores information about a lockfile
type LockfileInfo struct {
	Filename string               `json:"filename" jsonschema:"title=Filename,description=Name of the lockfile (e.g. package-lock.json go.sum)"`
	Content  string               `json:"content" jsonschema:"title=Content,description=Full content of the lockfile"`
	Digest   cryptoutil.DigestSet `json:"digest" jsonschema:"title=Digest,description=Cryptographic digests of the lockfile content"`
}

// Name returns the name of the attestation type
func (a *Attestor) Name() string {
	return "lockfiles"
}

// Attest captures the contents of common lockfiles
func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	lockfilePatterns := []string{
		"Gemfile.lock",      // Ruby
		"package-lock.json", // Node.js (npm)
		"yarn.lock",         // Node.js (Yarn)
		"Cargo.lock",        // Rust
		"poetry.lock",       // Python (Poetry)
		"Pipfile.lock",      // Python (Pipenv)
		"composer.lock",     // PHP
		"go.sum",            // Go
		"Podfile.lock",      // iOS/macOS (CocoaPods)
		"gradle.lockfile",   // Gradle
		"pnpm-lock.yaml",    // Node.js (pnpm)
	}

	a.Lockfiles = []LockfileInfo{}

	for _, pattern := range lockfilePatterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return fmt.Errorf("error searching for %s: %w", pattern, err)
		}

		for _, match := range matches {
			content, err := os.ReadFile(match)
			if err != nil {
				return fmt.Errorf("error reading %s: %w", match, err)
			}

			// Define required digest algorithms
			requiredDigestValues := []cryptoutil.DigestValue{
				{Hash: crypto.SHA256},
			}

			// Compute the digest of the lockfile content
			digest, err := cryptoutil.CalculateDigestSetFromBytes(content, requiredDigestValues)
			if err != nil {
				return fmt.Errorf("error computing digest of %s: %w", match, err)
			}

			a.Lockfiles = append(a.Lockfiles, LockfileInfo{
				Filename: filepath.Base(match),
				Content:  string(content),
				Digest:   digest,
			})
		}
	}

	return nil
}

// RunType implements attestation.Attestor.
func (o *Attestor) RunType() attestation.RunType {
	return RunType
}

// // Schema implements attestation.Attestor.
func (o *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&o)
}

// Type implements attestation.Attestor.
func (o *Attestor) Type() string {
	return Type
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	subjects := make(map[string]cryptoutil.DigestSet)
	for _, lockfile := range a.Lockfiles {
		subjectName := fmt.Sprintf("file:%s", lockfile.Filename)
		subjects[subjectName] = lockfile.Digest
	}
	return subjects
}

func (a *Attestor) Documentation() attestation.Documentation {
	return attestation.Documentation{
		Summary: "Captures dependency lockfiles from various package managers to ensure reproducible builds",
		Usage: []string{
			"Track exact dependency versions used in builds",
			"Detect dependency changes between builds",
			"Ensure build reproducibility across environments",
		},
		Example: "witness run -s install -k key.pem -a lockfiles -- npm ci",
	}
}
