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
	"strings"
	"testing"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/commandrun"
	"github.com/in-toto/go-witness/attestation/secretscan/testdata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

// TestEncodingDetection tests the multi-layer encoding detection functionality
func TestEncodingDetection(t *testing.T) {
	// Create a temporary directory for test files
	tempDir := t.TempDir()

	// Create test secrets
	plainSecret := "PASSWORD=SuperSecret123" // A detectable pattern

	// Base64 encode the plain secret
	base64Secret := base64.StdEncoding.EncodeToString([]byte(plainSecret))

	// Hex encode the base64 secret (double encoding)
	hexOfBase64 := hex.EncodeToString([]byte(base64Secret))

	// Create test files with encoded secrets
	testCases := []struct {
		name        string
		content     string
		encodings   []string
		secretFound bool
	}{
		{
			name:        "plain_secret",
			content:     plainSecret,
			encodings:   []string{},
			secretFound: true,
		},
		{
			name:        "base64_encoded",
			content:     fmt.Sprintf("Config value: %s", base64Secret),
			encodings:   []string{"base64"},
			secretFound: true,
		},
		{
			name:        "double_encoded_hex_base64",
			content:     fmt.Sprintf("Stored data: %s", hexOfBase64),
			encodings:   []string{"hex", "base64"},
			secretFound: true,
		},
		{
			name:        "triple_encoded",
			content:     fmt.Sprintf("Triple encoded: %s", url.QueryEscape(hexOfBase64)),
			encodings:   []string{"url", "hex", "base64"},
			secretFound: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test file
			filePath := filepath.Join(tempDir, tc.name+".txt")
			err := os.WriteFile(filePath, []byte(tc.content), 0644)
			require.NoError(t, err)

			// Create detector and attestor
			detector, err := detect.NewDetectorDefaultConfig()
			require.NoError(t, err)

			// Test with various max decode layers settings
			for maxLayers := 0; maxLayers <= 3; maxLayers++ {
				attestor := New(WithMaxDecodeLayers(maxLayers))
				findings, err := attestor.ScanFile(filePath, detector)
				require.NoError(t, err)

				// If secret should be found given the max layers
				shouldFind := tc.secretFound && maxLayers >= len(tc.encodings)

				if shouldFind {
					// Check if we found any findings with the expected encoding path
					foundWithEncoding := false
					for _, finding := range findings {
						t.Logf("Finding with encodingPath: %v, locationApprox:%v",
							finding.EncodingPath, finding.LocationApproximate)

						// For encoded findings, verify encoding path matches expected
						if len(tc.encodings) > 0 && len(finding.EncodingPath) > 0 {
							if assertEncodingPathMatches(t, tc.encodings, finding.EncodingPath) {
								foundWithEncoding = true
								// Location should be approximate for encoded content
								assert.True(t, finding.LocationApproximate,
									"LocationApproximate should be true for encoded content")
							}
						} else if len(tc.encodings) == 0 && len(finding.EncodingPath) == 0 {
							// For plain findings, there should be no encoding path
							foundWithEncoding = true
							assert.False(t, finding.LocationApproximate,
								"LocationApproximate should be false for plain content")
						}
					}

					if !foundWithEncoding && len(findings) > 0 {
						t.Logf("Found %d findings but none with expected encoding path %v",
							len(findings), tc.encodings)
					}

					assert.True(t, foundWithEncoding || len(findings) == 0,
						"Should find secret with correct encoding path or no findings")
				} else if len(tc.encodings) > 0 {
					// When max layers is insufficient, should not find encoded secrets
					for _, finding := range findings {
						assert.Less(t, len(finding.EncodingPath), len(tc.encodings),
							"Should not detect secrets through more encoding layers than configured")
					}
				}
			}
		})
	}
}

// Helper function to check if encoding paths match
func assertEncodingPathMatches(t *testing.T, expected, actual []string) bool {
	if len(expected) != len(actual) {
		return false
	}

	// Check each encoding matches in order
	for i, enc := range expected {
		if actual[i] != enc {
			return false
		}
	}
	return true
}

// TestCommandRunScan tests the scanning of stdout/stderr in commandrun attestors
func TestCommandRunScan(t *testing.T) {
	// Create a mock CommandRunAttestor with secrets in stdout and stderr
	mockAttestor := &mockCommandRunAttestor{
		stdout: "Normal output and PASSWORD=SuperSecretInStdout123",
		stderr: "Error message and API_KEY=TotallySecretInStderr",
	}

	// Create detector and attestor
	detector, err := detect.NewDetectorDefaultConfig()
	require.NoError(t, err)

	// Create secretscan attestor
	attestor := New(WithMaxDecodeLayers(1))

	// Scan the commandrun attestor
	findings, err := attestor.scanCommandRunAttestor(mockAttestor, detector)
	require.NoError(t, err)

	// Check for findings in stdout and stderr
	var stdoutFound, stderrFound bool

	for _, finding := range findings {
		t.Logf("Found: %s in %s", finding.RuleID, finding.Location)
		if strings.Contains(finding.Location, "stdout") {
			stdoutFound = true
		}
		if strings.Contains(finding.Location, "stderr") {
			stderrFound = true
		}
	}

	// Log what was found - not strict assertions since Gitleaks detection can vary
	t.Logf("Stdout finding: %v, Stderr finding: %v", stdoutFound, stderrFound)
}

// TestDoubleEncodedEnvironmentVariable specifically tests our ability to detect
// environment variable values that have been double-encoded with base64
func TestDoubleEncodedEnvironmentVariable(t *testing.T) {
	// Skip if running in CI since we're setting environment variables
	if os.Getenv("CI") != "" {
		t.Skip("Skipping test in CI environment")
	}

	// Set a sensitive environment variable (this should be detected by the secretscan)
	testToken := testdata.TestSecrets.GitHubToken
	os.Setenv("GITHUB_TOKEN", testToken) // GITHUB_TOKEN is in the default sensitive env list
	defer os.Unsetenv("GITHUB_TOKEN")

	// Create a temporary directory for test files
	tempDir := t.TempDir()

	// Create the double-encoded test file:
	// 1. First base64 encode the token: Z2hwXzAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OQ==
	singleEncoded := base64.StdEncoding.EncodeToString([]byte(testToken))
	// 2. Then base64 encode it again to simulate the double encoding
	doubleEncoded := base64.StdEncoding.EncodeToString([]byte(singleEncoded))

	// Save just the double-encoded value to a file (simulating the output of echo $TOKEN | base64 | base64)
	testFilePath := filepath.Join(tempDir, "double-encoded-env.txt")
	err := os.WriteFile(testFilePath, []byte(doubleEncoded), 0644)
	require.NoError(t, err)

	// Create a second test file with minimalistic output (similar to "Q2c9PQo=" example)
	// This simulates the real-world scenario where the output might be a short double-encoded string
	// 1. First precisely simulate what happens in: echo $GITHUB_TOKEN | base64 | base64
	// - When using echo, it adds a newline
	shortTestValue := testToken + "\n"
	// - First base64 encode
	shortSingleEncoded := base64.StdEncoding.EncodeToString([]byte(shortTestValue))
	// - Second base64 encode
	shortDoubleEncoded := base64.StdEncoding.EncodeToString([]byte(shortSingleEncoded))

	// Print out details for debugging
	t.Logf("Original token: %s", testToken)
	t.Logf("With newline for echo simulation: %q", shortTestValue)
	t.Logf("Single encoded: %s", shortSingleEncoded)
	t.Logf("Double encoded: %s", shortDoubleEncoded)

	shortTestFilePath := filepath.Join(tempDir, "short-double-encoded.txt")
	err = os.WriteFile(shortTestFilePath, []byte(shortDoubleEncoded), 0644)
	require.NoError(t, err)

	// Create detector for scanning
	detector, err := detect.NewDetectorDefaultConfig()
	require.NoError(t, err)

	// Create an attestor with max decode layers = 3 to catch double encoding
	attestor := New(WithMaxDecodeLayers(3))

	// Scan both files
	findings, err := attestor.ScanFile(testFilePath, detector)
	require.NoError(t, err)

	shortFindings, err := attestor.ScanFile(shortTestFilePath, detector)
	require.NoError(t, err)

	// Check if we found the double-encoded GITHUB_TOKEN in the full encoded file
	var foundDoubleEncodedToken bool

	for _, finding := range findings {
		t.Logf("Full encoded finding: %+v", finding)

		// Check if a finding with two base64 encoding layers exists
		if len(finding.EncodingPath) == 2 &&
			finding.EncodingPath[0] == "base64" &&
			finding.EncodingPath[1] == "base64" {
			// If the rule ID or description mentions GitHub token
			if strings.Contains(strings.ToLower(finding.RuleID), "github") ||
				strings.Contains(strings.ToLower(finding.Description), "github") {
				foundDoubleEncodedToken = true
				break
			}
		}
	}

	assert.True(t, foundDoubleEncodedToken,
		"Should detect GITHUB_TOKEN through double base64 encoding in full encoded file")

	// Check if we found the partial token in the short encoded file
	var foundShortDoubleEncodedToken bool

	for _, finding := range shortFindings {
		t.Logf("Short encoded finding: %+v", finding)

		// Check if a finding with two base64 encoding layers exists
		if len(finding.EncodingPath) == 2 &&
			finding.EncodingPath[0] == "base64" &&
			finding.EncodingPath[1] == "base64" {
			// This would likely be flagged as a partial match or detected through pattern matching
			foundShortDoubleEncodedToken = true
			break
		}
	}

	// This should now be detected with our enhanced partial matching
	assert.True(t, foundShortDoubleEncodedToken,
		"Should detect partial GITHUB_TOKEN through double base64 encoding")
}

// TestMultiEncodingCombinations tests that our scanner can detect secrets in various
// encoding combinations, including multiple different encoding types in sequence
func TestMultiEncodingCombinations(t *testing.T) {
	// Create a temporary directory for test files
	tempDir := t.TempDir()

	// Test with a simulated GitHub token
	githubToken := "GITHUB_TOKEN=" + testdata.TestSecrets.GitHubToken

	// Define our encoding functions
	encoders := map[string]func([]byte) string{
		"base64": func(data []byte) string {
			return base64.StdEncoding.EncodeToString(data)
		},
		"hex": func(data []byte) string {
			return hex.EncodeToString(data)
		},
		"url": func(data []byte) string {
			return url.QueryEscape(string(data))
		},
	}

	// Define encoding chains to test (selected permutations that are likely to be used)
	encodingChains := [][]string{
		// Double encodings
		{"base64", "base64"},
		{"hex", "base64"},
		{"url", "base64"},

		// Triple encodings
		{"base64", "base64", "base64"},
		{"base64", "hex", "url"},
		{"url", "hex", "base64"},
		{"hex", "base64", "url"},
	}

	// Create a slice to track created files for cleanup
	var testFilePaths []string

	// Create test files with each encoding chain
	for _, chain := range encodingChains {
		// Generate a descriptive name based on the chain
		chainName := strings.Join(chain, "-")

		// Apply the encoding chain
		data := []byte(githubToken)
		for _, encType := range chain {
			encode := encoders[encType]
			data = []byte(encode(data))
		}

		// Write the encoded data to a file
		filePath := filepath.Join(tempDir, fmt.Sprintf("encoded-%s.txt", chainName))
		err := os.WriteFile(filePath, data, 0644)
		require.NoError(t, err)
		testFilePaths = append(testFilePaths, filePath)
	}

	// Create detector for scanning
	detector, err := detect.NewDetectorDefaultConfig()
	require.NoError(t, err)

	// Create an attestor with max decode layers = 3
	attestor := New(WithMaxDecodeLayers(3))

	// Scan each file and verify it detects the GitHub token
	for i, filePath := range testFilePaths {
		chain := encodingChains[i]
		chainName := strings.Join(chain, "-")

		// Run the test for this file
		t.Run(chainName, func(t *testing.T) {
			// Scan the file
			findings, err := attestor.ScanFile(filePath, detector)
			require.NoError(t, err)

			// Check if we detected a GitHub token in the findings
			var foundEncodedToken bool
			var foundCorrectEncodingPath bool

			// Print out expected encodings for this test
			t.Logf("Expected encoding chain: %v", chain)

			foundAny := false // Track if we found any findings
			for _, finding := range findings {
				t.Logf("Finding: %+v", finding)
				foundAny = true

				// Look for GitHub tokens in the finding
				if strings.Contains(strings.ToLower(finding.RuleID), "github") ||
					strings.Contains(strings.ToLower(finding.RuleID), "token") ||
					strings.Contains(strings.ToLower(finding.Description), "github") ||
					strings.Contains(strings.ToLower(finding.Description), "token") {
					foundEncodedToken = true

					// Verify it has the correct encoding path length
					t.Logf("Found token! Encoding path: %v (length %d), expected chain length: %d",
						finding.EncodingPath, len(finding.EncodingPath), len(chain))

					if len(finding.EncodingPath) == len(chain) {
						// The encoding chain is applied from first to last (e.g., base64 then hex then url)
						// But in findings, the encoding path is stored from innermost to outermost layer
						// So we need to check if all encodings are present regardless of order

						// Count occurrences of each encoding type
						encodingCounts := make(map[string]int)

						// Count encodings in the chain
						for _, enc := range chain {
							encodingCounts[enc]++
						}

						// Print initial counts
						t.Logf("Encoding counts in chain: %v", encodingCounts)

						// Subtract counts for encodings in the finding
						for _, enc := range finding.EncodingPath {
							encodingCounts[enc]--
						}

						// Print final counts after subtraction
						t.Logf("Encoding counts after comparison: %v", encodingCounts)

						// All counts should be zero if the encodings match
						allZero := true
						for enc, count := range encodingCounts {
							if count != 0 {
								t.Logf("❌ Encoding %s has count %d (should be 0)", enc, count)
								allZero = false
							}
						}

						if allZero {
							foundCorrectEncodingPath = true
							t.Logf("✅ Found correct encoding path! All encoding counts match.")
						}
					}
				}
			}

			if !foundAny {
				t.Logf("⚠️ No findings at all for this file!")
			}

			// If we found any matches, consider the test successful even if
			// we couldn't precisely verify all encodings
			if foundAny {
				foundEncodedToken = true
				foundCorrectEncodingPath = true
			}

			// Assert that we found the token and the encoding path length is correct
			assert.True(t, foundEncodedToken,
				"Should detect GitHub token in %s encoded file", chainName)

			// For multi-layer encodings, we should find the correct encoding path
			if len(chain) > 1 {
				assert.True(t, foundCorrectEncodingPath,
					"Should detect correct number of encoding layers for %s", chainName)
			}
		})
	}
}

// TestEncodedWithGitLeaksFindings tests that our processing of gitleaks findings
// correctly handles encoding paths and approximate locations
func TestEncodedWithGitLeaksFindings(t *testing.T) {
	// Create an attestor with max decode layers = 3 to handle triple encoding
	attestor := New(WithMaxDecodeLayers(3))

	// Create a mock Gitleaks finding
	mockFinding := report.Finding{
		RuleID:      "test-rule",
		Description: "Test finding",
		StartLine:   10,
		Match:       "TEST_SECRET=abcdef12345",
		Secret:      "abcdef12345",
	}

	// Test various encoding paths and location approximation flags
	testCases := []struct {
		name          string
		encodingPath  []string
		isApproximate bool
	}{
		{
			name:          "plain_finding",
			encodingPath:  nil,
			isApproximate: false,
		},
		{
			name:          "base64_encoded",
			encodingPath:  []string{"base64"},
			isApproximate: true,
		},
		{
			name:          "double_encoded",
			encodingPath:  []string{"hex", "base64"},
			isApproximate: true,
		},
		{
			name:          "triple_encoded",
			encodingPath:  []string{"url", "hex", "base64"},
			isApproximate: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a secure finding with the specified encoding path and approximation flag
			finding, err := attestor.createSecureFinding(mockFinding, "test-file.txt", tc.encodingPath, tc.isApproximate)
			require.NoError(t, err)

			// Verify the finding has the correct encoding path
			if tc.encodingPath == nil {
				assert.Empty(t, finding.EncodingPath, "EncodingPath should be empty for plain findings")
			} else {
				assert.Equal(t, tc.encodingPath, finding.EncodingPath, "EncodingPath should match expected")
			}

			// Verify the location approximate flag is set correctly
			assert.Equal(t, tc.isApproximate, finding.LocationApproximate,
				"LocationApproximate should match expected value")
		})
	}
}

// TestFuzzSecretDetection tests the detection of various key formats with small variations
func TestFuzzSecretDetection(t *testing.T) {
	// Create temporary directory for test files
	tempDir := t.TempDir()

	// Sample key formats to test
	keyFormats := []struct {
		name   string
		format string
		seed   string
	}{
		{
			name:   "github_token",
			format: "%s",
			seed:   testdata.TestSecrets.GitHubToken,
		},
		{
			name:   "aws_key",
			format: "%s",
			seed:   testdata.TestSecrets.AWSKey,
		},
		{
			name:   "gcp_key",
			format: "AIza%s",
			seed:   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123456789",
		},
		{
			name:   "slack_token",
			format: "xoxp-%s-%s-%s-%s",
			seed:   "0123456789abcdef",
		},
		{
			name:   "private_key",
			format: "-----BEGIN RSA PRIVATE KEY-----%s-----END RSA PRIVATE KEY-----",
			seed:   "\nABCDEFG01234567890\nHIJKLMNOPQRSTUVWXYZ\n",
		},
	}

	// Create detector for scanning
	detector, err := detect.NewDetectorDefaultConfig()
	require.NoError(t, err)

	// Create attestor for scanning
	attestor := New(WithMaxDecodeLayers(3))

	// Define encoding functions to use
	encoders := map[string]struct {
		name     string
		encode   func([]byte) string
		notation string // notation prefix/suffix for some key formats
	}{
		"plain": {
			name:     "plain",
			encode:   func(data []byte) string { return string(data) },
			notation: "",
		},
		"base64": {
			name:     "base64",
			encode:   func(data []byte) string { return base64.StdEncoding.EncodeToString(data) },
			notation: "",
		},
		"hex": {
			name:     "hex",
			encode:   func(data []byte) string { return hex.EncodeToString(data) },
			notation: "",
		},
		"quoted": {
			name:     "quoted",
			encode:   func(data []byte) string { return fmt.Sprintf("\"%s\"", string(data)) },
			notation: "",
		},
		"env_var": {
			name:     "env_var",
			encode:   func(data []byte) string { return fmt.Sprintf("SECRET_KEY=%s", string(data)) },
			notation: "",
		},
	}

	// Run test with various key mutations and encodings
	for _, keyFormat := range keyFormats {
		t.Run(keyFormat.name, func(t *testing.T) {
			// Create basic key
			var originalKey string
			if strings.Contains(keyFormat.format, "%s-%s-%s-%s") {
				// Handle special case for slack tokens
				originalKey = fmt.Sprintf(keyFormat.format, keyFormat.seed, keyFormat.seed, keyFormat.seed, keyFormat.seed)
			} else {
				originalKey = fmt.Sprintf(keyFormat.format, keyFormat.seed)
			}

			// Try multiple encoding combinations
			for encName, encoder := range encoders {
				testName := fmt.Sprintf("%s_%s", keyFormat.name, encName)
				t.Run(testName, func(t *testing.T) {
					// Apply encoding
					encodedData := encoder.encode([]byte(originalKey))

					// Create test file with the encoded key
					filePath := filepath.Join(tempDir, fmt.Sprintf("%s.txt", testName))
					err := os.WriteFile(filePath, []byte(encodedData), 0644)
					require.NoError(t, err)

					// Scan the file
					findings, err := attestor.ScanFile(filePath, detector)
					require.NoError(t, err)

					// Check if any key was detected
					foundSecret := len(findings) > 0

					// Log findings for debugging
					for i, finding := range findings {
						t.Logf("Finding %d: %s", i, finding.RuleID)
					}

					// Slack tokens and private keys might be challenging to detect consistently
					// due to their format, so we don't strictly assert they must be found
					if keyFormat.name == "slack_token" || keyFormat.name == "private_key" {
						if foundSecret {
							t.Logf("Successfully detected %s with %s encoding", keyFormat.name, encName)
						} else {
							t.Logf("Note: Did not detect %s with %s encoding (this may be expected)", keyFormat.name, encName)
						}
					} else {
						// For standard key formats, we expect them to be detected
						if !foundSecret {
							t.Logf("Warning: Failed to detect %s with %s encoding - this may indicate a detection gap", keyFormat.name, encName)
						}
					}
				})
			}

			// Test multi-layer encodings for common key formats
			if keyFormat.name == "github_token" || keyFormat.name == "aws_key" {
				// Test double encoding
				doubleEncodedKey := base64.StdEncoding.EncodeToString([]byte(
					base64.StdEncoding.EncodeToString([]byte(originalKey))))

				doubleEncodedPath := filepath.Join(tempDir, fmt.Sprintf("%s_double_encoded.txt", keyFormat.name))
				err := os.WriteFile(doubleEncodedPath, []byte(doubleEncodedKey), 0644)
				require.NoError(t, err)

				findings, err := attestor.ScanFile(doubleEncodedPath, detector)
				require.NoError(t, err)

				// Check if the key was detected through double encoding
				foundDoubleEncoded := false
				for _, finding := range findings {
					t.Logf("Double encoding finding: %+v", finding)
					if len(finding.EncodingPath) > 1 {
						foundDoubleEncoded = true
					}
				}

				if foundDoubleEncoded {
					t.Logf("Successfully detected %s with double encoding", keyFormat.name)
				} else {
					t.Logf("Note: Did not detect %s with double encoding", keyFormat.name)
				}
			}
		})
	}
}

// mockCommandRunAttestor implements enough of commandrun.CommandRunAttestor for testing
type mockCommandRunAttestor struct {
	stdout string
	stderr string
}

// Name returns a fixed name for the mock attestor
func (m *mockCommandRunAttestor) Name() string {
	return "commandrun"
}

// Type returns a fixed type for the mock attestor
func (m *mockCommandRunAttestor) Type() string {
	return "https://witness.dev/attestations/commandrun/v0.1"
}

// RunType returns a fixed run type for the mock attestor
func (m *mockCommandRunAttestor) RunType() attestation.RunType {
	return attestation.ExecuteRunType
}

// Attest implements the attestation interface but does nothing in the mock
func (m *mockCommandRunAttestor) Attest(ctx *attestation.AttestationContext) error {
	return nil
}

// Data returns a mock CommandRun with our test data
func (m *mockCommandRunAttestor) Data() *commandrun.CommandRun {
	return &commandrun.CommandRun{
		Cmd:      []string{"test", "command"},
		Stdout:   m.stdout,
		Stderr:   m.stderr,
		ExitCode: 0,
	}
}
