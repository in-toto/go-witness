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
	"strings"
)

// isBinaryFile determines if a file is binary based on its MIME type
// Binary files are skipped during scanning to avoid false positives and improve performance
func isBinaryFile(mimeType string) bool {
	// Common binary MIME type prefixes
	binaryPrefixes := []string{
		"application/octet-stream",
		"application/x-executable",
		"application/x-mach-binary",
		"application/x-sharedlib",
		"application/x-object",
	}

	for _, prefix := range binaryPrefixes {
		if strings.HasPrefix(mimeType, prefix) {
			return true
		}
	}

	// Executable file MIME type suffixes
	executableSuffixes := []string{
		"/x-executable",
		"/x-sharedlib",
		"/x-mach-binary",
	}

	for _, suffix := range executableSuffixes {
		if strings.HasSuffix(mimeType, suffix) {
			return true
		}
	}

	return false
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// truncateMatch safely truncates the match string to avoid exposing full secrets
// It keeps a short prefix and suffix while replacing the middle with "..."
func truncateMatch(match string) string {
	if len(match) > maxMatchDisplayLength {
		return match[:truncatedMatchSegmentLength] + "..." + match[len(match)-truncatedMatchSegmentLength:]
	}
	return match
}
