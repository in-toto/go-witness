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

package secretscan

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/in-toto/go-witness/attestation/secretscan/testdata"
	"github.com/zricethezav/gitleaks/v8/detect"
)

// FuzzEncodingCombinations tests all combinations of encodings for secret detection
func FuzzEncodingCombinations(f *testing.F) {
	// Add seeds for different combinations of encodings
	// Format: rawSecret, encodingChain
	// Encoding chain is a string of encoding types separated by commas

	// Test single layer encodings
	f.Add(testdata.TestSecrets.GitHubToken, "base64")
	f.Add(testdata.TestSecrets.GitHubToken, "hex")
	f.Add(testdata.TestSecrets.GitHubToken, "url")

	// Test double layer encodings
	f.Add(testdata.TestSecrets.GitHubToken, "base64,base64")
	f.Add(testdata.TestSecrets.GitHubToken, "base64,hex")
	f.Add(testdata.TestSecrets.GitHubToken, "base64,url")
	f.Add(testdata.TestSecrets.GitHubToken, "hex,base64")
	f.Add(testdata.TestSecrets.GitHubToken, "hex,url")
	f.Add(testdata.TestSecrets.GitHubToken, "url,base64")
	f.Add(testdata.TestSecrets.GitHubToken, "url,hex")

	// Test triple layer encodings
	f.Add(testdata.TestSecrets.GitHubToken, "base64,base64,base64")
	f.Add(testdata.TestSecrets.GitHubToken, "hex,base64,url")
	f.Add(testdata.TestSecrets.GitHubToken, "url,hex,base64")

	// Test with different secret types (using obviously fake examples)
	f.Add(testdata.TestSecrets.AWSKey, "base64,hex,url")                                                                            // Fake AWS key
	f.Add("AIza0000000000000000000000000TEST", "url,base64")                                                                        // Fake Google API key
	f.Add("xoxp-0000000000-0000000000-0000000000-000000000000test", "base64")                                                       // Fake Slack token
	f.Add("sk_test_0000000000000000000000000000test", "hex,base64")                                                                 // Fake Stripe key (using test prefix)
	f.Add("SG.000000000000000000000000.0000000000000000000000000000000000000", "base64,url")                                        // Fake SendGrid key
	f.Add("-----BEGIN EXAMPLE RSA KEY-----\nTESTKEY\n-----END EXAMPLE RSA KEY-----", "base64")                                      // Fake private key
	f.Add("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ", "url") // JWT
	f.Add("https://username:password@example.com", "base64,hex")                                                                    // Basic auth URL

	// Test non-standard encodings
	f.Add(testdata.TestSecrets.GitHubToken, "base64,base64,base64,base64") // Deep nesting
	f.Add(testdata.TestSecrets.GitHubToken, "base64,hex,base64,url")       // Mixed encoding chains

	// Edge cases that might cause issues
	f.Add(strings.Repeat("A", 1000)+testdata.TestSecrets.GitHubToken, "base64") // Very long string with secret at the end
	f.Add("ghp_"+strings.Repeat("0123456789", 100), "base64")                   // Extremely long token/key
	f.Add("ghp_\t\n\r 012345678901234567890123456789", "base64")                // Whitespace in key
	f.Add("ghp_\u0000\u0001\u0002\u00030123456789", "base64")                   // Control characters
	f.Add("ghp_🔑🔒🔓012345678901234567890123456789", "base64")                    // Unicode/emoji
	f.Add("ghp_", "base64")                                                     // Very short potential key prefix
	f.Add("A"+string([]byte{0xff, 0xfe, 0xfd})+"ghp_0123456789", "hex")         // Invalid UTF-8

	// Malformed encodings
	f.Add(testdata.TestSecrets.GitHubToken, "base64,broken") // Invalid encoding type
	f.Add("Z==", "base64")                                   // Invalid base64 (wrong padding)
	f.Add("====", "base64")                                  // Invalid base64 (only padding)

	// Boundary cases
	f.Add("this contains ghp_012345678901234567890123456789 in the middle", "base64") // Token in the middle of text
	f.Add("ghp_012345678901234567890123456789\nAKIAIOSFODNN7EXAMPLE", "base64")       // Multiple secrets
	f.Add("Z2hwXzAxMjM0NTY3ODkwMTIzNA==Z2hwXzAxMjM0NTY3ODkwMTIzNA==", "")             // Already encoded tokens concatenated

	// Fuzz target that tests encoding chains
	f.Fuzz(func(t *testing.T, rawSecret string, encodingChain string) {
		// Skip empty inputs
		if len(rawSecret) == 0 || len(encodingChain) == 0 {
			return
		}

		// Parse the encoding chain
		encodings := strings.Split(encodingChain, ",")

		// Create a temporary directory for testing
		tempDir := t.TempDir()

		// Apply the encoding chain
		encodedSecret := rawSecret
		for _, encType := range encodings {
			// Apply current encoding layer
			switch strings.ToLower(encType) {
			case "base64":
				encodedSecret = base64.StdEncoding.EncodeToString([]byte(encodedSecret))
			case "hex":
				encodedSecret = hex.EncodeToString([]byte(encodedSecret))
			case "url":
				encodedSecret = url.QueryEscape(encodedSecret)
			default:
				// Skip invalid encoding types
				t.Logf("Skipping unknown encoding type: %s", encType)
				continue
			}
		}

		// Create file with the encoded content
		filePath := filepath.Join(tempDir, fmt.Sprintf("fuzz_encoded_%s.txt", strings.Join(encodings, "_")))
		err := os.WriteFile(filePath, []byte(encodedSecret), 0644)
		if err != nil {
			t.Logf("Failed to write test file: %v", err)
			return
		}

		// Create detector for scanning
		detector, err := detect.NewDetectorDefaultConfig()
		if err != nil {
			t.Logf("Failed to create detector: %v", err)
			return
		}

		// Create attestor with enough decode layers
		attestor := New(WithMaxDecodeLayers(len(encodings) + 1)) // +1 for safety

		// Scan the file
		findings, err := attestor.ScanFile(filePath, detector)
		if err != nil {
			// Log error but don't fail - this is a fuzzing test
			t.Logf("Error scanning file: %v", err)
			return
		}

		// Don't assert anything specific - fuzzing looks for crashes
		// But log interesting findings for debug purposes
		if len(findings) > 0 {
			t.Logf("Found %d secrets with encoding chain: %s", len(findings), encodingChain)

			// Check if the number of encoding layers matches our expectation
			for i, finding := range findings {
				t.Logf("Finding %d: EncodingPath=%v, LocationApproximate=%v",
					i, finding.EncodingPath, finding.LocationApproximate)

				// Check if the encoding path has at least the expected number of layers
				if len(finding.EncodingPath) < len(encodings) {
					t.Logf("Warning: Expected at least %d encoding layers, found %d",
						len(encodings), len(finding.EncodingPath))
				}
			}
		} else {
			t.Logf("No secrets found with encoding chain: %s", encodingChain)
		}
	})
}

// FuzzDetectionWithEnvVars tests detection of environment variable values with various encodings
func FuzzDetectionWithEnvVars(f *testing.F) {
	// Add seeds
	f.Add("GITHUB_TOKEN", testdata.TestSecrets.GitHubToken, "base64")
	f.Add("AWS_SECRET", testdata.TestSecrets.AWSKey, "hex,base64")
	f.Add("STRIPE_API_KEY", "sk_test_0000000000000000000000000000test", "base64")
	f.Add("SENDGRID_API_KEY", "SG.000000000000000000000000.0000000000000000000000000000000000000", "base64,url")
	f.Add("JWT_SECRET", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ", "url")

	// Edge cases
	f.Add("ENV_WITH_SPECIAL_CHARS", "abc!@#$%^&*()_+-=[]{}|;':\",./<>?", "base64")    // Special characters
	f.Add("ENV_WITH_EMOJI", "password🔑123", "hex")                                    // Emoji in value
	f.Add("ENV_WITH_WHITESPACE", "secret with spaces\ttabs\nand\rnewlines", "base64") // Whitespace
	f.Add("ENV_WITH_UNICODE", "пароль密码パスワード암호", "base64")                            // Unicode characters
	f.Add("ENV_VERY_SHORT", "a", "base64")                                            // Very short value
	f.Add("ENV_EMPTY", "", "base64")                                                  // Empty value
	f.Add("ENV_VERY_LONG", strings.Repeat("password123", 100), "base64")              // Very long value
	f.Add("", "secret123", "base64")                                                  // Empty env var name
	f.Add("ENV_WEIRD_NAME!@#", "secret123", "base64")                                 // Special chars in name
	f.Add(strings.Repeat("ENV_", 50), "secret123", "base64")                          // Very long env var name

	// Fuzz target
	f.Fuzz(func(t *testing.T, envVarName, envVarValue, encodingChain string) {
		// Skip empty inputs or inputs with invalid UTF-8 sequences
		if len(envVarName) == 0 || len(envVarValue) == 0 {
			return
		}

		// Validate inputs don't contain invalid UTF-8 sequences
		if !utf8.ValidString(envVarName) || !utf8.ValidString(envVarValue) || !utf8.ValidString(encodingChain) {
			return
		}

		// Skip if environment variable name isn't a valid regex pattern
		// This will help prevent regex compilation errors
		if _, err := regexp.Compile(regexp.QuoteMeta(envVarValue)); err != nil {
			return
		}

		// Set the environment variable
		os.Setenv(envVarName, envVarValue)
		defer os.Unsetenv(envVarName)

		// Parse the encoding chain
		var encodings []string
		if encodingChain != "" {
			encodings = strings.Split(encodingChain, ",")
		}

		// Apply the encoding chain
		encodedValue := envVarValue
		for _, encType := range encodings {
			// Apply current encoding layer
			switch strings.ToLower(encType) {
			case "base64":
				encodedValue = base64.StdEncoding.EncodeToString([]byte(encodedValue))
			case "hex":
				encodedValue = hex.EncodeToString([]byte(encodedValue))
			case "url":
				encodedValue = url.QueryEscape(encodedValue)
			default:
				// Skip invalid encoding types
				continue
			}
		}

		// Create a temporary directory for testing
		tempDir := t.TempDir()

		// Create file with the encoded environment variable value
		filePath := filepath.Join(tempDir, fmt.Sprintf("fuzz_env_var_%s.txt", envVarName))
		err := os.WriteFile(filePath, []byte(encodedValue), 0644)
		if err != nil {
			t.Logf("Failed to write test file: %v", err)
			return
		}

		// Create detector for scanning
		detector, err := detect.NewDetectorDefaultConfig()
		if err != nil {
			t.Logf("Failed to create detector: %v", err)
			return
		}

		// Create attestor with enough decode layers
		attestor := New(WithMaxDecodeLayers(len(encodings) + 1)) // +1 for safety

		// Scan the file
		findings, err := attestor.ScanFile(filePath, detector)
		if err != nil {
			// Log but don't fail the test
			t.Logf("Error scanning file: %v", err)
			return
		}

		// For environment variables, just log findings
		if len(findings) > 0 {
			t.Logf("Found %d secrets for env var %s with encoding chain: %s",
				len(findings), envVarName, encodingChain)

			// Check encoding paths
			for i, finding := range findings {
				t.Logf("Finding %d: EncodingPath=%v", i, finding.EncodingPath)

				// Look for env var detection in rule ID or description
				if strings.Contains(finding.RuleID, strings.ToLower(envVarName)) ||
					strings.Contains(finding.Description, envVarName) {
					t.Logf("  ✓ Successfully detected environment variable %s", envVarName)
				}
			}
		}
	})
}
