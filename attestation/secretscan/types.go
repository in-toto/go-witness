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
	"os"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	_ "github.com/invopop/jsonschema" // Used for schema generation
)

const (
	// Name is the attestor name used in the attestation registry
	Name = "secretscan"

	// Type is the attestation type URI that identifies this attestor
	Type = "https://witness.dev/attestations/secretscan/v0.1"

	// RunType specifies when this attestor runs in the pipeline
	// PostProductRunType ensures it runs after all products are generated
	RunType = attestation.PostProductRunType
)

// Verify the Attestor implements the required interfaces at compile time
var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
)

// Attestor scans products and attestations for secrets and sensitive information.
// It implements the attestation.Attestor interface to integrate with the Witness
// attestation pipeline and provides these security features:
//
//  1. Secret Securing: Detected secrets are replaced with cryptographic hashes
//     using configured digest algorithms to prevent secret exposure
//
//  2. Multi-layer Encoding Detection: Can detect secrets hidden through multiple
//     layers of encoding (base64, hex, URL encoding)
//
//  3. Resource Protection: Limits file size and recursion depth to prevent
//     resource exhaustion attacks
//
//  4. False Positive Reduction: Supports allowlisting through regex patterns,
//     specific strings, and path patterns
//
//  5. Configurable Response: Can be set to fail the attestation process when
//     secrets are detected
//
// The attestor runs after all product attestors to analyze both products and
// attestations, adding scanned products as subjects for verifiability.
type Attestor struct {
	// Configuration options
	failOnDetection bool        // Whether to fail the attestation when secrets are found
	maxFileSizeMB   int         // Maximum file size to scan in MB
	filePerm        os.FileMode // File permissions for temporary files
	allowList       *AllowList  // Patterns to ignore during scanning
	configPath      string      // Path to custom Gitleaks config file
	maxDecodeLayers int         // Maximum layers of encoding to decode

	// Results and state
	Findings []Finding                       `json:"findings"` // List of detected secrets
	subjects map[string]cryptoutil.DigestSet // Products that were scanned

	// Context for the attestation
	ctx *attestation.AttestationContext // Reference to attestation context
}

// Finding represents a detected secret with the sensitive data securely replaced
// by cryptographic digests. It provides detailed information about where and how
// the secret was detected while ensuring the actual secret value is never stored.
type Finding struct {
	// RuleID identifies which detection rule triggered the finding
	RuleID string `json:"ruleId" jsonschema:"title=Rule ID,description=Detection rule that found the secret"`

	// Description provides a human-readable explanation of the finding
	Description string `json:"description" jsonschema:"title=Description,description=Human-readable explanation of the finding"`

	// Location indicates where the secret was found in the form:
	// "attestation:attestor-name" or "product:/path/to/file"
	Location string `json:"location" jsonschema:"title=Location,description=Where the secret was found (attestation:name or product:path)"`

	// Line indicates the line number where the secret was found
	Line int `json:"startLine" jsonschema:"title=Line Number,description=Line number where the secret was found"`

	// Secret contains multiple cryptographic hashes of the secret
	// This allows for verification without exposing the actual secret value
	Secret cryptoutil.DigestSet `json:"secret,omitempty" jsonschema:"title=Secret Digest,description=Cryptographic hashes of the detected secret"`

	// Match contains a redacted snippet showing context around the secret
	// The actual secret is truncated to prevent exposure
	Match string `json:"match,omitempty" jsonschema:"title=Match Context,description=Redacted snippet showing context around the secret"`

	// Entropy is the information density score (higher values indicate
	// more random/high-entropy content likely to be secrets)
	Entropy float32 `json:"entropy,omitempty" jsonschema:"title=Entropy,description=Information density score (higher indicates more random content)"`

	// EncodingPath tracks the sequence of encodings that were applied to
	// hide the secret, listed from outermost to innermost layer
	EncodingPath []string `json:"encodingPath,omitempty" jsonschema:"title=Encoding Path,description=Sequence of encodings applied to hide the secret"`

	// LocationApproximate indicates if the line number is approximate
	// This is true for secrets found in decoded content since the
	// original line number cannot be precisely determined
	LocationApproximate bool `json:"locationApproximate,omitempty" jsonschema:"title=Location Approximate,description=Whether the line number is approximate"`
}

// AllowList defines patterns that should be ignored during secret scanning.
// It helps reduce false positives by excluding known safe patterns.
type AllowList struct {
	// Description explains the purpose of this allowlist
	Description string `json:"description,omitempty" jsonschema:"title=Description,description=Purpose of this allowlist"`

	// Paths are file path patterns to ignore (regex format)
	Paths []string `json:"paths,omitempty" jsonschema:"title=Paths,description=File path patterns to ignore (regex format)"`

	// Regexes are content patterns to ignore (regex format)
	Regexes []string `json:"regexes,omitempty" jsonschema:"title=Regexes,description=Content patterns to ignore (regex format)"`

	// StopWords are specific strings to ignore (exact match)
	StopWords []string `json:"stopWords,omitempty" jsonschema:"title=Stop Words,description=Specific strings to ignore (exact match)"`
}

// matchInfo holds information about a pattern match in content
type matchInfo struct {
	lineNumber   int    // Line number where the match occurred
	matchContext string // Context surrounding the match
}

// encodingScanner defines the components for handling one encoding type
type encodingScanner struct {
	Name    string                                 // Name of the encoding (base64, hex, url)
	Finder  func(content string) []string          // Function to find encoded strings
	Decoder func(candidate string) ([]byte, error) // Function to decode strings
}
