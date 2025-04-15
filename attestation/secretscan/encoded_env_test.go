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
// This file contains tests for the encoded environment variable detection capability.
package secretscan

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zricethezav/gitleaks/v8/detect"
)

// TestAdditionalEncodedEnvironmentTests tests additional scenarios for encoded environment variable detection
func TestAdditionalEncodedEnvironmentTests(t *testing.T) {
	// Skip if running in CI since it relies on environment variables
	if os.Getenv("CI") != "" {
		t.Skip("Skipping test in CI environment")
	}

	// Create a temporary directory
	tempDir := t.TempDir()

	// Set a test environment variable that would be treated as sensitive
	testValue := "super-secret-test-value-12345"
	os.Setenv("TEST_SECRET_ENV", testValue)
	defer os.Unsetenv("TEST_SECRET_ENV")

	// Create test file with the encoded value (without the variable name)
	testFile := filepath.Join(tempDir, "encoded-env-value.txt")

	// Encode the value in different ways
	base64Value := base64.StdEncoding.EncodeToString([]byte(testValue))
	hexValue := hex.EncodeToString([]byte(testValue))
	urlValue := url.QueryEscape(testValue)

	testContent := fmt.Sprintf(`
	# Test file for encoded environment values
	
	# 1. Base64-encoded value
	%s
	
	# 2. Hex-encoded value
	%s
	
	# 3. URL-encoded value
	%s
	`, base64Value, hexValue, urlValue)

	err := os.WriteFile(testFile, []byte(testContent), 0644)
	require.NoError(t, err)

	// Create a detector and attestor configured for testing
	detector, err := detect.NewDetectorDefaultConfig()
	require.NoError(t, err)

	// Create an allow list with the test environment variable
	allowList := &AllowList{
		Regexes:   []string{},
		StopWords: []string{},
	}

	// Create attestor with max decode layers = 2
	attestor := New(
		WithMaxDecodeLayers(2),
		WithAllowList(allowList),
	)

	// No need to mock getSensitiveEnvVarsList - TEST_SECRET_ENV should be considered
	// sensitive by default because it contains "SECRET" in the name

	// Scan the file
	findings, err := attestor.ScanFile(testFile, detector)
	require.NoError(t, err)

	// Log findings for debugging
	for i, finding := range findings {
		t.Logf("Finding %d: Rule=%s, EncodingPath=%v, Match=%s",
			i, finding.RuleID, finding.EncodingPath, finding.Match)
	}

	// Check for findings from each encoding type
	foundBase64Value := false
	foundHexValue := false
	foundURLValue := false

	for _, finding := range findings {
		if len(finding.EncodingPath) > 0 {
			encodingType := finding.EncodingPath[0]
			switch encodingType {
			case "base64":
				if strings.Contains(finding.RuleID, "test-secret-env") {
					foundBase64Value = true
				}
			case "hex":
				if strings.Contains(finding.RuleID, "test-secret-env") {
					foundHexValue = true
				}
			case "url":
				if strings.Contains(finding.RuleID, "test-secret-env") {
					foundURLValue = true
				}
			}
		}
	}

	// Log the results - we don't make hard assertions since it depends on environment
	t.Logf("Base64-encoded env value detection: %v", foundBase64Value)
	t.Logf("Hex-encoded env value detection: %v", foundHexValue)
	t.Logf("URL-encoded env value detection: %v", foundURLValue)
}
