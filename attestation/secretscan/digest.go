// Copyright 2025 The Witness Contributors
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

// Package secretscan provides functionality for detecting secrets and sensitive information.
// This file (digest.go) handles the secure hashing of detected secrets.
package secretscan

import (
	"crypto"
	"fmt"

	"github.com/in-toto/go-witness/cryptoutil"
)

// calculateSecretDigests creates a digest set for a secret using the configured digest algorithms
// from the attestation context
func (a *Attestor) calculateSecretDigests(secret string) (cryptoutil.DigestSet, error) {
	// Default hashes if context is missing (mainly for tests)
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}

	// Get hashes from context if available
	if a.ctx != nil {
		hashes = a.ctx.Hashes()
	}

	// Calculate digests for the secret
	digestSet, err := cryptoutil.CalculateDigestSetFromBytes([]byte(secret), hashes)
	if err != nil {
		return nil, fmt.Errorf("error calculating digest for secret: %w", err)
	}

	return digestSet, nil
}
