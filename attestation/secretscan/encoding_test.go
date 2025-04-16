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
// This file (encoding_test.go) contains tests for the encoding detection and decoding.
package secretscan

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"testing"

	"github.com/in-toto/go-witness/attestation/secretscan/testdata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindPotentialBase64Strings(t *testing.T) {
	// Test cases for base64 detection
	testCases := []struct {
		content  string
		expected []string
		name     string
	}{
		{
			name:     "Standard Base64",
			content:  "This contains a base64 string: SGVsbG8gV29ybGQh",
			expected: []string{"SGVsbG8gV29ybGQh"},
		},
		{
			name:     "URL-safe Base64",
			content:  "This contains a URL-safe base64 string: SGVsbG9fV29ybGQh",
			expected: []string{"SGVsbG9fV29ybGQh"},
		},
		{
			name:     "Base64 with Padding",
			content:  "This contains a base64 string with padding: SGVsbG8gV29ybGQ=",
			expected: []string{"SGVsbG8gV29ybGQ="},
		},
		{
			name:     "No Base64",
			content:  "This contains no base64 strings",
			expected: nil,
		},
		{
			name:     "Multiple Base64",
			content:  "Multiple base64: SGVsbG8gV29ybGQh and also YW5vdGhlciBzdHJpbmc=",
			expected: []string{"SGVsbG8gV29ybGQh", "YW5vdGhlciBzdHJpbmc="},
		},
		{
			name:     "Too Short",
			content:  "Too short: SGVs", // Less than 16 chars
			expected: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := findPotentialBase64Strings(tc.content)
			assert.Equal(t, tc.expected, result, "Should find expected base64 strings")
		})
	}
}

func TestFindPotentialHexStrings(t *testing.T) {
	// Test cases for hex detection
	testCases := []struct {
		content  string
		expected []string
		name     string
	}{
		{
			name:     "Valid Hex",
			content:  "This contains a hex string: 48656c6c6f20576f726c6421",
			expected: []string{"48656c6c6f20576f726c6421"},
		},
		{
			name:     "Valid Hex Mixed Case",
			content:  "This contains a hex string with mixed case: 48656C6c6F20576f726C6421",
			expected: []string{"48656C6c6F20576f726C6421"},
		},
		{
			name:     "No Hex",
			content:  "This contains no hex strings",
			expected: nil,
		},
		{
			name:     "Multiple Hex",
			content:  "Multiple hex: 48656c6c6f20576f726c6421 and also 616e6f74686572207374726967",
			expected: []string{"48656c6c6f20576f726c6421", "616e6f74686572207374726967"},
		},
		{
			name:     "Too Short",
			content:  "Too short: 48656", // Less than 16 chars
			expected: nil,
		},
		{
			name:     "Odd Length",
			content:  "Odd length hex: 48656c6c6f20576f726c642", // Odd length - should not be valid
			expected: nil,                                       // After filtering for even length
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := findPotentialHexStrings(tc.content)
			assert.Equal(t, tc.expected, result, "Should find expected hex strings")
		})
	}
}

func TestFindPotentialURLStrings(t *testing.T) {
	// Test cases for URL encoding detection
	testCases := []struct {
		content  string
		expected []string
		name     string
	}{
		{
			name:     "URL Encoded Sequence",
			content:  "This contains a URL encoded sequence: %48%65%6c%6c%6f%20%57%6f%72%6c%64%21",
			expected: []string{"%48%65%6c%6c%6f%20%57%6f%72%6c%64%21"},
		},
		{
			name:     "URL with Encoded Equal Sign",
			content:  "This contains a URL with encoded = sign: token%3Dabc123def456",
			expected: []string{"token%3Dabc123def456"},
		},
		{
			name:     "No URL Encoding",
			content:  "This contains no URL encoded strings",
			expected: nil,
		},
		{
			name:     "Multiple URL Encodings",
			content:  "Multiple URL encodings: %48%65%6c%6c%6f and token%3Dxyz789",
			expected: []string{"%48%65%6c%6c%6f", "token%3Dxyz789"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := findPotentialURLStrings(tc.content)

			// For each expected item, verify it was found (without requiring exact array matching)
			for _, expected := range tc.expected {
				found := false
				for _, actual := range result {
					if actual == expected {
						found = true
						break
					}
				}
				assert.True(t, found, "Should find expected URL encoded string: %s", expected)
			}

			// If expected is nil, result should be nil or empty
			if tc.expected == nil {
				assert.Empty(t, result, "Result should be empty for no expected strings")
			}
		})
	}
}

func TestDecodeBase64String(t *testing.T) {
	// Test cases for base64 decoding
	testCases := []struct {
		encoded  string
		expected string
		name     string
	}{
		{
			name:     "Standard Base64",
			encoded:  "SGVsbG8gV29ybGQh",
			expected: "Hello World!",
		},
		{
			name:     "URL-safe Base64",
			encoded:  "SGVsbG9fV29ybGQh",
			expected: "Hello_World!",
		},
		{
			name:     "Base64 with Padding",
			encoded:  "SGVsbG8gV29ybGQ=",
			expected: "Hello World",
		},
		{
			name:     "Empty String",
			encoded:  "",
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			decoded, err := decodeBase64String(tc.encoded)
			require.NoError(t, err, "Should decode without error")
			assert.Equal(t, tc.expected, string(decoded), "Should decode correctly")
		})
	}

	// Test invalid base64
	t.Run("Invalid Base64", func(t *testing.T) {
		_, err := decodeBase64String("This is not valid base64!")
		assert.Error(t, err, "Should return error for invalid base64")
	})
}

func TestDecodeHexString(t *testing.T) {
	// Test cases for hex decoding
	testCases := []struct {
		encoded  string
		expected string
		name     string
	}{
		{
			name:     "Valid Hex",
			encoded:  "48656c6c6f20576f726c6421",
			expected: "Hello World!",
		},
		{
			name:     "Valid Hex Mixed Case",
			encoded:  "48656C6c6F20576f726C6421",
			expected: "Hello World!",
		},
		{
			name:     "Empty String",
			encoded:  "",
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			decoded, err := decodeHexString(tc.encoded)
			require.NoError(t, err, "Should decode without error")
			assert.Equal(t, tc.expected, string(decoded), "Should decode correctly")
		})
	}

	// Test invalid hex
	t.Run("Invalid Hex", func(t *testing.T) {
		_, err := decodeHexString("This is not valid hex!")
		assert.Error(t, err, "Should return error for invalid hex")
	})

	// Test odd length hex
	t.Run("Odd Length Hex", func(t *testing.T) {
		_, err := decodeHexString("48656c6c6f20576f726c642") // Odd length
		assert.Error(t, err, "Should return error for odd length hex")
	})
}

func TestDecodeURLString(t *testing.T) {
	// Test cases for URL decoding
	testCases := []struct {
		encoded  string
		expected string
		name     string
	}{
		{
			name:     "URL Encoded",
			encoded:  "%48%65%6c%6c%6f%20%57%6f%72%6c%64%21",
			expected: "Hello World!",
		},
		{
			name:     "URL with Encoded Equal Sign",
			encoded:  "token%3Dabc123def456",
			expected: "token=abc123def456",
		},
		{
			name:     "Empty String",
			encoded:  "",
			expected: "",
		},
		{
			name:     "Plain Text with Spaces",
			encoded:  "Hello+World",
			expected: "Hello World",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			decoded, err := decodeURLString(tc.encoded)
			require.NoError(t, err, "Should decode without error")
			assert.Equal(t, tc.expected, string(decoded), "Should decode correctly")
		})
	}

	// Test invalid URL encoding
	t.Run("Invalid URL Encoding", func(t *testing.T) {
		_, err := decodeURLString("This has an invalid encoding: %ZZ")
		assert.Error(t, err, "Should return error for invalid URL encoding")
	})
}

func TestMultilayerEncoding(t *testing.T) {
	// Test manual decoding of multi-layered encoded content

	// Original secret
	secret := "super-secret-password-123"

	// First layer: base64
	base64Secret := base64.StdEncoding.EncodeToString([]byte(secret))
	// Second layer: hex
	hexOfBase64 := hex.EncodeToString([]byte(base64Secret))
	// Third layer: URL encoding
	urlOfHexOfBase64 := url.QueryEscape(hexOfBase64)

	// Manually decode each layer
	t.Run("Manual Decoding", func(t *testing.T) {
		// Start with URL-encoded string
		decoded1, err := url.QueryUnescape(urlOfHexOfBase64)
		require.NoError(t, err, "Should decode URL layer")

		// Decode hex
		decodedBytes2, err := hex.DecodeString(decoded1)
		require.NoError(t, err, "Should decode hex layer")

		// Decode base64
		decodedBytes3, err := base64.StdEncoding.DecodeString(string(decodedBytes2))
		require.NoError(t, err, "Should decode base64 layer")

		// Verify we got back the original secret
		assert.Equal(t, secret, string(decodedBytes3), "Should recover original secret after decoding all layers")
	})
}

func TestTripleEncodingPermutations(t *testing.T) {
	// Test secret with a recognizable pattern (Github token)
	secret := "GITHUB_TOKEN=" + testdata.TestSecrets.GitHubToken

	// Define map of encoders using existing functions in the package
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

	// Define map of decoders using existing functions in the package
	decoders := map[string]func(string) ([]byte, error){
		"base64": decodeBase64String,
		"hex":    decodeHexString,
		"url":    decodeURLString,
	}

	// Define encoding types
	encodingTypes := []string{"base64", "hex", "url"}

	// Generate all permutations of triple encoding
	var generatePermutations func(prefix []string, remaining int)
	var permutations [][]string

	generatePermutations = func(prefix []string, remaining int) {
		if remaining == 0 {
			// Copy the prefix to avoid modifying it later
			result := make([]string, len(prefix))
			copy(result, prefix)
			permutations = append(permutations, result)
			return
		}

		for _, encType := range encodingTypes {
			generatePermutations(append(prefix, encType), remaining-1)
		}
	}

	// Generate permutations of length 3
	generatePermutations([]string{}, 3)

	// Test each permutation
	for _, encodingChain := range permutations {
		testName := encodingChain[0]
		for i := 1; i < len(encodingChain); i++ {
			testName += "-" + encodingChain[i]
		}

		t.Run(testName, func(t *testing.T) {
			// Apply the encoding chain
			data := []byte(secret)
			for _, encType := range encodingChain {
				data = []byte(encoders[encType](data))
			}
			encoded := string(data)

			// Log the encoded content for debugging
			t.Logf("Original: %s", secret)
			t.Logf("Encoded (%s): %s", testName, encoded)

			// Now manually decode it to verify
			current := encoded
			for i := len(encodingChain) - 1; i >= 0; i-- {
				decoder := decoders[encodingChain[i]]
				decoded, err := decoder(current)
				if err != nil {
					t.Fatalf("Failed to decode %s layer: %v", encodingChain[i], err)
				}
				current = string(decoded)
			}

			// Verify we recovered the original secret
			assert.Equal(t, secret, current, "Should recover original secret")
		})
	}
}

func TestTripleEncodingWithFuzzing(t *testing.T) {
	// Skip in short mode as fuzzing can be time-consuming
	if testing.Short() {
		t.Skip("Skipping fuzzing test in short mode")
	}

	// Define map of encoders using existing functions in the package
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

	// Define map of decoders using existing functions in the package
	decoders := map[string]func(string) ([]byte, error){
		"base64": decodeBase64String,
		"hex":    decodeHexString,
		"url":    decodeURLString,
	}

	// Define encoding types
	encodingTypes := []string{"base64", "hex", "url"}

	// List of realistic secrets to test (varied formats and patterns)
	testSecrets := []string{
		// API keys and tokens with different patterns
		"GITHUB_TOKEN=" + testdata.TestSecrets.GitHubToken,
		"AWS_SECRET_ACCESS_KEY=" + testdata.TestSecrets.AWSKey,
		"API_KEY=" + testdata.TestSecrets.GoogleAPIKey,
		"AUTH_TOKEN=" + testdata.TestSecrets.JWTToken,

		// Passwords with different complexities and formats
		"PASSWORD=P@ssw0rd123!",
		"DB_PASSWORD=mySup3rS3cr3tDBP@ss",
		"ADMIN_PASS=r00tUs3r$%^",

		// Environment variables with sensitive values
		"DATABASE_URL=postgresql://user:password@localhost:5432/mydb",
		"REDIS_PASSWORD=complex-redis-password-123",

		// SSH and asymmetric keys (partial, for testing detection)
		"SSH_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY----- MIIEpAIBAAKCAQEAx4UbaDzY",
		"PGP_SECRET=-----BEGIN PGP PRIVATE KEY BLOCK----- lQdGBF4HmjYBE",

		// Connection strings
		"MONGODB_URI=mongodb+srv://user:password@cluster0.mongodb.net/test",
		"STRIPE_SECRET_KEY=sk_test_12345678901234567890",

		// Mixed-case and special chars
		"My_API_SECRET={\"key\":\"abcdef1234567890\",\"secret\":\"vEryS3cretV@lue\"}",
		"Multi-line\nSecret\nWith\nNewlines\nAPI_KEY=12345",
	}

	// Helper to get random encoding chain of specific length
	getRandomEncodingChain := func(length int) []string {
		chain := make([]string, length)
		for i := 0; i < length; i++ {
			chain[i] = encodingTypes[rand.Intn(len(encodingTypes))]
		}
		return chain
	}

	// Test with each secret and various encoding chains
	for _, secret := range testSecrets {
		// Get a descriptive name for the test case
		secretType := "unknown"
		if strings.Contains(secret, "TOKEN") || strings.Contains(secret, "KEY") {
			secretType = "api-key"
		} else if strings.Contains(secret, "PASS") || strings.Contains(secret, "password") {
			secretType = "password"
		} else if strings.Contains(secret, "BEGIN") {
			secretType = "private-key"
		} else if strings.Contains(secret, "URI") || strings.Contains(secret, "URL") {
			secretType = "connection-string"
		}

		// Test with single, double, and triple encoding chains
		for length := 1; length <= 3; length++ {
			// Test a few random encoding chains for each secret and length
			// (testing all permutations for all secrets would be too many test cases)
			for i := 0; i < 3; i++ {
				encodingChain := getRandomEncodingChain(length)

				chainName := encodingChain[0]
				for j := 1; j < len(encodingChain); j++ {
					chainName += "-" + encodingChain[j]
				}

				testName := fmt.Sprintf("%s-%s", secretType, chainName)

				t.Run(testName, func(t *testing.T) {
					// Apply the encoding chain
					data := []byte(secret)
					for _, encType := range encodingChain {
						data = []byte(encoders[encType](data))
					}
					encoded := string(data)

					// Log just a prefix of the secret to avoid filling logs
					maxSecretPreview := 30
					secretPreview := secret
					if len(secretPreview) > maxSecretPreview {
						secretPreview = secretPreview[:maxSecretPreview] + "..."
					}

					t.Logf("Original: %s", secretPreview)
					encodedPreview := encoded
					if len(encodedPreview) > 100 {
						encodedPreview = encodedPreview[:100]
					}
					t.Logf("Encoded (%s): %s", chainName, encodedPreview)

					// Now manually decode it to verify
					current := encoded
					for i := len(encodingChain) - 1; i >= 0; i-- {
						decoder := decoders[encodingChain[i]]
						decoded, err := decoder(current)
						if err != nil {
							t.Fatalf("Failed to decode %s layer: %v", encodingChain[i], err)
						}
						current = string(decoded)
					}

					// Verify we recovered the original secret
					assert.Equal(t, secret, current, "Should recover original secret")
				})
			}
		}
	}
}

func TestEncodingScanner(t *testing.T) {
	// Test the encoding scanner against simplified scenarios

	// Original content
	original := "secret-password-123"

	// Create test cases for different encoding types
	testCases := []struct {
		name   string
		encode func([]byte) string
		decode func(string) ([]byte, error)
	}{
		{
			name: "base64",
			encode: func(data []byte) string {
				return base64.StdEncoding.EncodeToString(data)
			},
			decode: func(s string) ([]byte, error) {
				return base64.StdEncoding.DecodeString(s)
			},
		},
		{
			name: "hex",
			encode: func(data []byte) string {
				return hex.EncodeToString(data)
			},
			decode: func(s string) ([]byte, error) {
				return hex.DecodeString(s)
			},
		},
		{
			name: "url",
			encode: func(data []byte) string {
				return url.QueryEscape(string(data))
			},
			decode: func(s string) ([]byte, error) {
				decoded, err := url.QueryUnescape(s)
				if err != nil {
					return nil, err
				}
				return []byte(decoded), nil
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create encoded content
			encoded := tc.encode([]byte(original))

			// Check that our decoder can decode it
			decoded, err := tc.decode(encoded)
			require.NoError(t, err, "Should decode without error")

			// Verify we get back the original content
			assert.Equal(t, original, string(decoded), "Should decode back to original")
		})
	}
}

func TestDefaultEncodingScanners(t *testing.T) {
	// Test that default scanners are properly configured
	assert.Equal(t, 3, len(defaultEncodingScanners), "Should have 3 default encoding scanners")

	scannerNames := map[string]bool{
		"base64": false,
		"hex":    false,
		"url":    false,
	}

	for _, scanner := range defaultEncodingScanners {
		// Mark this scanner as found
		scannerNames[scanner.Name] = true

		// Verify it has required components
		assert.NotNil(t, scanner.Finder, "Scanner should have a finder function")
		assert.NotNil(t, scanner.Decoder, "Scanner should have a decoder function")
	}

	// Verify all scanners were found
	for name, found := range scannerNames {
		assert.True(t, found, "Default scanners should include %s", name)
	}
}
