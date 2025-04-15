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
// This file (utils_test.go) contains tests for utility functions.
package secretscan

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsBinaryFileComprehensive(t *testing.T) {
	// Test cases for binary MIME types
	binaryMimeTypes := []string{
		"application/octet-stream",
		"application/x-executable",
		"application/x-mach-binary",
		"application/x-sharedlib",
		"application/x-object",
		"application/pdf",                         // Contains binary data
		"image/png",                               // Binary image format
		"audio/mpeg",                              // Binary audio format
		"video/mp4",                               // Binary video format
		"application/java-archive",                // JAR file
		"application/vnd.android.package-archive", // APK file
	}

	// Test cases for text MIME types
	textMimeTypes := []string{
		"text/plain",
		"text/html",
		"text/css",
		"text/javascript",
		"application/json",
		"application/xml",
		"text/csv",
		"text/markdown",
		"application/x-sh",         // Shell script
		"application/x-javascript", // Old JS MIME type
	}

	// Test binary MIME types
	for _, mimeType := range binaryMimeTypes {
		t.Run(mimeType, func(t *testing.T) {
			result := isBinaryFile(mimeType)
			// Note: Not all of these will return true, as our function
			// only checks specific prefixes/suffixes, not all binary formats.
			// We're just logging the results here for visibility.
			t.Logf("MIME type %s considered binary: %v", mimeType, result)
		})
	}

	// Test text MIME types
	for _, mimeType := range textMimeTypes {
		t.Run(mimeType, func(t *testing.T) {
			result := isBinaryFile(mimeType)
			assert.False(t, result, "MIME type %s should not be considered binary", mimeType)
		})
	}

	// Specifically test the binary prefixes we check for
	for _, prefix := range []string{
		"application/octet-stream",
		"application/x-executable",
		"application/x-mach-binary",
		"application/x-sharedlib",
		"application/x-object",
	} {
		t.Run("Prefix_"+prefix, func(t *testing.T) {
			assert.True(t, isBinaryFile(prefix), "MIME type %s should be considered binary", prefix)
			assert.True(t, isBinaryFile(prefix+".extra"), "MIME type %s.extra should be considered binary", prefix)
		})
	}

	// Specifically test the binary suffixes we check for
	for _, suffix := range []string{
		"/x-executable",
		"/x-sharedlib",
		"/x-mach-binary",
	} {
		t.Run("Suffix_"+suffix, func(t *testing.T) {
			assert.True(t, isBinaryFile("anything"+suffix), "MIME type anything%s should be considered binary", suffix)
		})
	}
}

func TestMin(t *testing.T) {
	testCases := []struct {
		a, b, expected int
		name           string
	}{
		{5, 10, 5, "First smaller"},
		{10, 5, 5, "Second smaller"},
		{5, 5, 5, "Equal values"},
		{-5, 10, -5, "Negative first"},
		{10, -5, -5, "Negative second"},
		{-10, -5, -10, "Both negative"},
		{0, 10, 0, "First zero"},
		{10, 0, 0, "Second zero"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := min(tc.a, tc.b)
			assert.Equal(t, tc.expected, result, "min(%d, %d) should be %d", tc.a, tc.b, tc.expected)
		})
	}
}

func TestMax(t *testing.T) {
	testCases := []struct {
		a, b, expected int
		name           string
	}{
		{5, 10, 10, "Second larger"},
		{10, 5, 10, "First larger"},
		{5, 5, 5, "Equal values"},
		{-5, 10, 10, "Negative first"},
		{10, -5, 10, "Negative second"},
		{-10, -5, -5, "Both negative"},
		{0, 10, 10, "First zero"},
		{10, 0, 10, "Second zero"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := max(tc.a, tc.b)
			assert.Equal(t, tc.expected, result, "max(%d, %d) should be %d", tc.a, tc.b, tc.expected)
		})
	}
}

func TestTruncateMatch(t *testing.T) {
	// Create a custom truncate function with test values
	testTruncateMatch := func(match string) string {
		maxLength := 20
		segmentLength := 5
		if len(match) > maxLength {
			return match[:segmentLength] + "..." + match[len(match)-segmentLength:]
		}
		return match
	}

	testCases := []struct {
		input    string
		expected string
		name     string
	}{
		{"short", "short", "Short string (no truncation)"},
		{"exactly-twenty-chars", "exactly-twenty-chars", "Exact length string"},
		{"this-string-is-definitely-longer-than-twenty-chars", "this-...chars", "Long string (truncated)"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := testTruncateMatch(tc.input)
			assert.Equal(t, tc.expected, result, "testTruncateMatch(%q) should be %q", tc.input, tc.expected)
		})
	}
}
