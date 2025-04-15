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
// This file (digest_test.go) contains tests for secret digest calculations.
package secretscan

import (
	"crypto"
	"testing"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalculateSecretDigestsWithContext(t *testing.T) {
	// Create attestor
	attestor := New()

	// Create context with specific hash algorithms
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{attestor},
		attestation.WithHashes([]cryptoutil.DigestValue{
			{Hash: crypto.SHA256},
			{Hash: crypto.SHA512},
		}),
	)
	require.NoError(t, err)
	attestor.ctx = ctx

	// Test secret
	secret := "test-secret-value"

	// Calculate digests
	digestSet, err := attestor.calculateSecretDigests(secret)
	require.NoError(t, err, "calculateSecretDigests should not error")

	// Verify that the digest set contains entries for both configured hash algorithms
	assert.Contains(t, digestSet, cryptoutil.DigestValue{Hash: crypto.SHA256},
		"DigestSet should contain SHA256 entry")
	assert.Contains(t, digestSet, cryptoutil.DigestValue{Hash: crypto.SHA512},
		"DigestSet should contain SHA512 entry")

	// Verify hash values are present and have correct format
	sha256Value, exists := digestSet[cryptoutil.DigestValue{Hash: crypto.SHA256}]
	assert.True(t, exists, "SHA256 hash should exist in digest set")
	assert.NotEmpty(t, sha256Value, "SHA256 hash value should not be empty")

	sha512Value, exists := digestSet[cryptoutil.DigestValue{Hash: crypto.SHA512}]
	assert.True(t, exists, "SHA512 hash should exist in digest set")
	assert.NotEmpty(t, sha512Value, "SHA512 hash value should not be empty")
}

func TestCalculateSecretDigestsWithoutContext(t *testing.T) {
	// Create attestor with no context
	attestor := New()
	attestor.ctx = nil

	// Test secret
	secret := "test-secret-value"

	// Calculate digests
	digestSet, err := attestor.calculateSecretDigests(secret)
	require.NoError(t, err, "calculateSecretDigests should not error")

	// Verify that the digest set contains an entry for the default hash algorithm (SHA256)
	assert.Contains(t, digestSet, cryptoutil.DigestValue{Hash: crypto.SHA256},
		"DigestSet should contain SHA256 entry")

	// Verify hash value is present and has correct format
	sha256Value, exists := digestSet[cryptoutil.DigestValue{Hash: crypto.SHA256}]
	assert.True(t, exists, "SHA256 hash should exist in digest set")
	assert.NotEmpty(t, sha256Value, "SHA256 hash value should not be empty")
}

func TestCalculateSecretDigestsConsistency(t *testing.T) {
	// Create attestor
	attestor := New()

	// Test that same input produces same output
	secret := "test-secret-value"

	// Calculate digests twice
	digestSet1, err := attestor.calculateSecretDigests(secret)
	require.NoError(t, err, "calculateSecretDigests should not error on first call")

	digestSet2, err := attestor.calculateSecretDigests(secret)
	require.NoError(t, err, "calculateSecretDigests should not error on second call")

	// Verify that the hash values are the same
	for digestAlg, hash1 := range digestSet1 {
		hash2, exists := digestSet2[digestAlg]
		assert.True(t, exists, "Hash algorithm should exist in both digest sets")
		assert.Equal(t, hash1, hash2, "Hash values should be equal for the same input")
	}
}

func TestCalculateSecretDigestsDifferentInputs(t *testing.T) {
	// Create attestor
	attestor := New()

	// Test that different inputs produce different outputs
	secret1 := "test-secret-value-1"
	secret2 := "test-secret-value-2"

	// Calculate digests for both secrets
	digestSet1, err := attestor.calculateSecretDigests(secret1)
	require.NoError(t, err, "calculateSecretDigests should not error for secret1")

	digestSet2, err := attestor.calculateSecretDigests(secret2)
	require.NoError(t, err, "calculateSecretDigests should not error for secret2")

	// Verify that the hash values are different
	for digestAlg, hash1 := range digestSet1 {
		hash2, exists := digestSet2[digestAlg]
		assert.True(t, exists, "Hash algorithm should exist in both digest sets")
		assert.NotEqual(t, hash1, hash2, "Hash values should be different for different inputs")
	}
}
