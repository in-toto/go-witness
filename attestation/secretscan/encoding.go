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
	"net/url"
	"regexp"
)

// defaultEncodingScanners defines the encoding detection and decoding strategies
// Each scanner contains the encoding name, a function to find potential encoded strings,
// and a function to decode those strings
var defaultEncodingScanners = []encodingScanner{
	{"base64", findPotentialBase64Strings, decodeBase64String},
	{"hex", findPotentialHexStrings, decodeHexString},
	{"url", findPotentialURLStrings, decodeURLString},
}

// Regular expressions for detecting various encoded content
var (
	// Base64 patterns (standard and URL-safe with possible padding)
	// Minimum length 15 to reduce false positives
	base64Regex = regexp.MustCompile(`[A-Za-z0-9+/]{15,}={0,2}|[A-Za-z0-9_-]{15,}={0,2}`)

	// Hex pattern (even length and at least 16 chars for security-relevant content)
	hexRegex = regexp.MustCompile(`[0-9a-fA-F]{16,}`)

	// URL encoded patterns
	// Pattern for consecutive URL encodings (at least 3 hex-encoded chars)
	urlEncodedRegex = regexp.MustCompile(`(%[0-9a-fA-F]{2}){3,}`)

	// Pattern for detecting tokens with encoded equals sign (%3D)
	urlEqualSignRegex = regexp.MustCompile(`[A-Za-z0-9_-]{2,}%3D[A-Za-z0-9_%\-]{2,}`)
)

// findPotentialBase64Strings identifies possible base64 encoded strings in content
func findPotentialBase64Strings(content string) []string {
	return base64Regex.FindAllString(content, -1)
}

// findPotentialHexStrings identifies possible hex encoded strings in content
// and validates they have an even length (valid hex encoding)
func findPotentialHexStrings(content string) []string {
	hexMatches := hexRegex.FindAllString(content, -1)
	if len(hexMatches) == 0 {
		return nil
	}

	validHex := make([]string, 0, len(hexMatches))
	for _, match := range hexMatches {
		if len(match)%2 == 0 {
			validHex = append(validHex, match)
		}
	}

	if len(validHex) == 0 {
		return nil
	}

	return validHex
}

// findPotentialURLStrings identifies possible URL encoded strings in content
// using multiple pattern matching strategies
func findPotentialURLStrings(content string) []string {
	var matches []string

	// Find matches for standard URL encoding patterns
	urlMatches := urlEncodedRegex.FindAllString(content, -1)
	if len(urlMatches) > 0 {
		matches = append(matches, urlMatches...)
	}

	// Find URL encodings containing %3D (encoded = sign, common in tokens)
	equalSignMatches := urlEqualSignRegex.FindAllString(content, -1)
	if len(equalSignMatches) > 0 {
		if matches == nil {
			matches = equalSignMatches
		} else {
			matches = append(matches, equalSignMatches...)
		}
	}

	// Remove duplicates from the combined match set
	if len(matches) == 0 {
		return nil
	}

	seenMatches := make(map[string]struct{})
	uniqueMatches := make([]string, 0, len(matches))
	for _, match := range matches {
		if _, seen := seenMatches[match]; !seen {
			seenMatches[match] = struct{}{}
			uniqueMatches = append(uniqueMatches, match)
		}
	}

	return uniqueMatches
}

// decodeBase64String attempts to decode a base64 string
// It tries both standard base64 and URL-safe base64 encodings
func decodeBase64String(encoded string) ([]byte, error) {
	// Try standard base64 first
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err == nil {
		return decoded, nil
	}

	// Fall back to URL-safe base64 if standard decoding fails
	return base64.RawURLEncoding.DecodeString(encoded)
}

// decodeHexString attempts to decode a hex string
func decodeHexString(encoded string) ([]byte, error) {
	return hex.DecodeString(encoded)
}

// decodeURLString attempts to decode a URL encoded string
func decodeURLString(encoded string) ([]byte, error) {
	decodedStr, err := url.QueryUnescape(encoded)
	if err != nil {
		return nil, err
	}
	return []byte(decodedStr), nil
}
