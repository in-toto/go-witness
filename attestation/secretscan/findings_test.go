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
// This file (findings_test.go) contains tests for findings handling.
package secretscan

import (
	"crypto"
	"testing"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zricethezav/gitleaks/v8/report"
)

func TestProcessGitleaksFindings(t *testing.T) {
	// Create mock Gitleaks findings
	gitleaksFindings := []report.Finding{
		{
			RuleID:      "test-rule-1",
			Description: "Test finding 1",
			StartLine:   10,
			Match:       "API_KEY=12345",
			Secret:      "12345",
		},
		{
			RuleID:      "test-rule-2",
			Description: "Test finding 2",
			StartLine:   20,
			Match:       "password=secret",
			Secret:      "secret",
		},
	}

	// Test cases with different attestor configurations
	testCases := []struct {
		name                 string
		configPath           string
		allowList            *AllowList
		expectedFindingCount int
	}{
		{
			name:                 "No allowlist",
			configPath:           "",
			allowList:            nil,
			expectedFindingCount: 2, // Should keep all findings
		},
		{
			name:       "Manual allowlist with match",
			configPath: "",
			allowList: &AllowList{
				StopWords: []string{"API_KEY=12345"}, // Should match first finding
			},
			expectedFindingCount: 1, // Should filter out first finding
		},
		{
			name:       "Custom config path with allowlist (should ignore manual list)",
			configPath: "/path/to/config.toml",
			allowList: &AllowList{
				StopWords: []string{"API_KEY=12345", "password=secret"}, // Should match both findings
			},
			expectedFindingCount: 2, // Should ignore manual allowlist
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create attestor with test configuration
			attestor := New(
				WithConfigPath(tc.configPath),
				WithAllowList(tc.allowList),
			)

			// Initialize hash for attestor context
			ctx, err := attestation.NewContext("test",
				[]attestation.Attestor{attestor},
				attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
			)
			require.NoError(t, err)
			attestor.ctx = ctx

			// Process findings
			processedInThisScan := make(map[string]struct{})
			findings := attestor.processGitleaksFindings(
				gitleaksFindings,
				"test-file.txt",
				false,
				processedInThisScan,
			)

			// Verify findings count
			assert.Equal(t, tc.expectedFindingCount, len(findings),
				"Should return expected number of findings after filtering")

			// Verify findings format
			for _, finding := range findings {
				assert.NotEmpty(t, finding.RuleID, "Finding should have RuleID")
				assert.NotEmpty(t, finding.Description, "Finding should have Description")
				assert.Equal(t, "test-file.txt", finding.Location, "Finding should have correct Location")
				assert.NotEmpty(t, finding.Secret, "Finding should have Secret")
			}

			// Verify duplicate detection
			// Process the same findings again - should get no results since they're in processedInThisScan
			secondProcessing := attestor.processGitleaksFindings(
				gitleaksFindings,
				"test-file.txt",
				false,
				processedInThisScan,
			)
			assert.Empty(t, secondProcessing, "Should not return duplicates when processing same findings again")
		})
	}
}

func TestCreateSecureFinding(t *testing.T) {
	// Create attestor with hash configuration
	attestor := New()
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{attestor},
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
	)
	require.NoError(t, err)
	attestor.ctx = ctx

	// Create a mock Gitleaks finding
	mockFinding := report.Finding{
		RuleID:      "TEST-RULE", // Will be lowercased
		Description: "Test finding",
		StartLine:   42,
		Match:       "This is a very long match string that should be truncated in the output",
		Secret:      "secret-value-123",
	}

	// Test case variations
	testCases := []struct {
		name          string
		encodingPath  []string
		isApproximate bool
	}{
		{
			name:          "No encoding path",
			encodingPath:  nil,
			isApproximate: false,
		},
		{
			name:          "With encoding path",
			encodingPath:  []string{"base64", "hex"},
			isApproximate: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a secure finding
			finding, err := attestor.createSecureFinding(
				mockFinding,
				"test-file.txt",
				tc.encodingPath,
				tc.isApproximate,
			)
			require.NoError(t, err, "createSecureFinding should not error")

			// Verify finding fields
			assert.Equal(t, "test-rule", finding.RuleID, "RuleID should be lowercase")
			assert.Equal(t, mockFinding.Description, finding.Description, "Description should match")
			assert.Equal(t, "test-file.txt", finding.Location, "Location should match")
			assert.Equal(t, mockFinding.StartLine, finding.Line, "Line should match")
			assert.NotEqual(t, mockFinding.Match, finding.Match, "Match should be truncated")
			assert.True(t, len(finding.Match) <= maxMatchDisplayLength, "Match should not exceed max length")
			assert.Contains(t, finding.Secret, cryptoutil.DigestValue{Hash: crypto.SHA256}, "Secret should include SHA256 hash")

			// Verify encoding path
			if tc.encodingPath == nil {
				assert.Empty(t, finding.EncodingPath, "EncodingPath should be empty when no path provided")
			} else {
				assert.Equal(t, tc.encodingPath, finding.EncodingPath, "EncodingPath should match provided path")
			}

			// Verify approximate location
			assert.Equal(t, tc.isApproximate, finding.LocationApproximate, "LocationApproximate should match provided value")
		})
	}
}

func TestCalculateSecretDigests(t *testing.T) {
	// Test with context
	t.Run("With context", func(t *testing.T) {
		// Create attestor with hash configuration
		attestor := New()
		ctx, err := attestation.NewContext("test",
			[]attestation.Attestor{attestor},
			attestation.WithHashes([]cryptoutil.DigestValue{
				{Hash: crypto.SHA256},
				{Hash: crypto.SHA384},
			}),
		)
		require.NoError(t, err)
		attestor.ctx = ctx

		// Calculate digests
		digestSet, err := attestor.calculateSecretDigests("test-secret")
		require.NoError(t, err, "calculateSecretDigests should not error")

		// Verify digest set includes configured hashes
		assert.Contains(t, digestSet, cryptoutil.DigestValue{Hash: crypto.SHA256}, "DigestSet should contain SHA256")
		assert.Contains(t, digestSet, cryptoutil.DigestValue{Hash: crypto.SHA384}, "DigestSet should contain SHA384")
	})

	// Test without context (default hash)
	t.Run("Without context", func(t *testing.T) {
		attestor := New()
		// No context set (nil)

		// Calculate digests
		digestSet, err := attestor.calculateSecretDigests("test-secret")
		require.NoError(t, err, "calculateSecretDigests should not error")

		// Verify digest set includes default hash
		assert.Contains(t, digestSet, cryptoutil.DigestValue{Hash: crypto.SHA256}, "DigestSet should contain default SHA256")
	})
}

func TestSetAttestationLocation(t *testing.T) {
	// Create test findings
	findings := []Finding{
		{
			RuleID:      "test-rule-1",
			Description: "Test finding 1",
			Location:    "original-location-1",
		},
		{
			RuleID:      "test-rule-2",
			Description: "Test finding 2",
			Location:    "original-location-2",
		},
	}

	// Set attestation location
	attestor := New()
	attestor.setAttestationLocation(findings, "test-attestor")

	// Verify location format
	for _, finding := range findings {
		assert.Equal(t, "attestation:test-attestor", finding.Location,
			"Location should be formatted as attestation:name")
	}
}

func TestSetProductLocation(t *testing.T) {
	// Create test findings
	findings := []Finding{
		{
			RuleID:      "test-rule-1",
			Description: "Test finding 1",
			Location:    "original-location-1",
		},
		{
			RuleID:      "test-rule-2",
			Description: "Test finding 2",
			Location:    "original-location-2",
		},
	}

	// Set product location
	attestor := New()
	attestor.setProductLocation(findings, "/path/to/product.txt")

	// Verify location format
	for _, finding := range findings {
		assert.Equal(t, "product:/path/to/product.txt", finding.Location,
			"Location should be formatted as product:path")
	}
}
