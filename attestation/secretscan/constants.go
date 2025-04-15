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

const (
	// Default configuration values
	defaultFailOnDetection = false // Default behavior is to log secrets without failing
	defaultMaxFileSizeMB   = 10    // Maximum file size to scan (in MB)
	defaultFilePerm        = 0600  // Restrictive file permissions (owner read/write only)
	defaultAllowList       = ""    // No default allowlist
	defaultConfigPath      = ""    // No default custom Gitleaks config path
	defaultMaxDecodeLayers = 3     // Maximum recursion depth for decoding encoded content

	// Content matching and display constants
	defaultMatchContextSize     = 10                  // Characters before/after match in pattern matches
	redactionMatchContextSize   = 15                  // Characters before/after match in redacted output
	redactedValuePlaceholder    = "[SENSITIVE-VALUE]" // Placeholder for redacted sensitive values
	minSensitiveValueLength     = 4                   // Minimum length for sensitive values to be scanned
	maxMatchDisplayLength       = 40                  // Maximum length of match string in findings
	truncatedMatchSegmentLength = 8                   // Length of prefix/suffix shown in truncated matches
	maxScanRecursionDepth       = 3                   // Safety limit for recursive scanning to prevent stack overflow
)
