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
	"fmt"
	"os"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/registry"
	"github.com/invopop/jsonschema"
)

// Option is a function type for configuring attestor options
type Option func(*Attestor)

// WithFailOnDetection configures the attestor to fail when secrets are detected
// When enabled, the attestation process will fail if any secrets are found
func WithFailOnDetection(failOnDetection bool) Option {
	return func(a *Attestor) {
		a.failOnDetection = failOnDetection
	}
}

// WithMaxFileSize sets the maximum file size in MB that will be scanned
// This helps prevent resource exhaustion when scanning large files
func WithMaxFileSize(maxFileSizeMB int) Option {
	return func(a *Attestor) {
		if maxFileSizeMB > 0 {
			a.maxFileSizeMB = maxFileSizeMB
		}
	}
}

// WithFilePermissions sets the file permissions used for temporary files
// More restrictive permissions improve security
func WithFilePermissions(perm os.FileMode) Option {
	return func(a *Attestor) {
		a.filePerm = perm
	}
}

// WithAllowList configures patterns that should be allowed and not reported as secrets
// This helps reduce false positives by ignoring known acceptable matches
func WithAllowList(allowList *AllowList) Option {
	return func(a *Attestor) {
		a.allowList = allowList
	}
}

// WithConfigPath sets a custom Gitleaks configuration file path
// This allows using a full Gitleaks configuration TOML file for custom rules
func WithConfigPath(configPath string) Option {
	return func(a *Attestor) {
		a.configPath = configPath
	}
}

// WithMaxDecodeLayers sets the maximum number of encoding layers to decode
// This limits recursion depth when searching for secrets in encoded content
func WithMaxDecodeLayers(maxDecodeLayers int) Option {
	return func(a *Attestor) {
		if maxDecodeLayers >= 0 {
			a.maxDecodeLayers = maxDecodeLayers
		}
	}
}

// New creates a new Attestor with the given options
// It initializes the attestor with default values and applies any provided options
func New(opts ...Option) *Attestor {
	a := &Attestor{
		failOnDetection: defaultFailOnDetection,
		maxFileSizeMB:   defaultMaxFileSizeMB,
		filePerm:        defaultFilePerm,
		allowList:       nil,
		configPath:      defaultConfigPath,
		maxDecodeLayers: defaultMaxDecodeLayers,
		subjects:        make(map[string]cryptoutil.DigestSet),
	}

	for _, opt := range opts {
		opt(a)
	}

	return a
}

// Name returns the attestor name
func (a *Attestor) Name() string {
	return Name
}

// Type returns the attestation type URI
func (a *Attestor) Type() string {
	return Type
}

// RunType returns when this attestor runs in the pipeline
func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

// Schema returns the JSON schema for this attestor
func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(a)
}

// Subjects returns the products that were scanned as subjects
// This allows verification that the right products were examined
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	return a.subjects
}

// init registers the attestor with the attestation registry
// This makes it available to the Witness CLI and API
func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor { return New() },
		// Option: Fail when secrets are detected (default: false)
		registry.BoolConfigOption(
			"fail-on-detection",
			"Fail the attestation process if secrets are detected",
			defaultFailOnDetection,
			func(a attestation.Attestor, failOnDetection bool) (attestation.Attestor, error) {
				secretscanAttestor, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a secretscan attestor", a)
				}

				WithFailOnDetection(failOnDetection)(secretscanAttestor)
				return secretscanAttestor, nil
			},
		),

		// Option: Maximum file size to scan (default: 10MB)
		registry.IntConfigOption(
			"max-file-size-mb",
			"Maximum file size to scan in megabytes",
			defaultMaxFileSizeMB,
			func(a attestation.Attestor, maxFileSizeMB int) (attestation.Attestor, error) {
				secretscanAttestor, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a secretscan attestor", a)
				}

				WithMaxFileSize(maxFileSizeMB)(secretscanAttestor)
				return secretscanAttestor, nil
			},
		),

		// Option: Maximum decode layers for encoded secrets (default: 3)
		registry.IntConfigOption(
			"max-decode-layers",
			"Maximum number of encoding layers to decode when searching for secrets",
			defaultMaxDecodeLayers,
			func(a attestation.Attestor, maxDecodeLayers int) (attestation.Attestor, error) {
				secretscanAttestor, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a secretscan attestor", a)
				}

				WithMaxDecodeLayers(maxDecodeLayers)(secretscanAttestor)
				return secretscanAttestor, nil
			},
		),

		// Option: Custom Gitleaks config file path
		registry.StringConfigOption(
			"config-path",
			"Path to custom Gitleaks configuration file",
			defaultConfigPath,
			func(a attestation.Attestor, configPath string) (attestation.Attestor, error) {
				secretscanAttestor, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a secretscan attestor", a)
				}

				WithConfigPath(configPath)(secretscanAttestor)
				return secretscanAttestor, nil
			},
		),

		// Option: Allowlist regex patterns (can be specified multiple times)
		registry.StringConfigOption(
			"allowlist-regex",
			"Regex pattern for content to ignore (can be specified multiple times)",
			"",
			func(a attestation.Attestor, regexPattern string) (attestation.Attestor, error) {
				secretscanAttestor, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a secretscan attestor", a)
				}

				if regexPattern == "" {
					return secretscanAttestor, nil
				}

				// Initialize allowList if it doesn't exist
				if secretscanAttestor.allowList == nil {
					secretscanAttestor.allowList = &AllowList{
						Description: "Witness secretscan allowlist",
					}
				}

				// Add regex to allowlist
				secretscanAttestor.allowList.Regexes = append(secretscanAttestor.allowList.Regexes, regexPattern)
				return secretscanAttestor, nil
			},
		),

		// Option: Allowlist stop words (can be specified multiple times)
		registry.StringConfigOption(
			"allowlist-stopword",
			"Specific string to ignore (can be specified multiple times)",
			"",
			func(a attestation.Attestor, stopWord string) (attestation.Attestor, error) {
				secretscanAttestor, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a secretscan attestor", a)
				}

				if stopWord == "" {
					return secretscanAttestor, nil
				}

				// Initialize allowList if it doesn't exist
				if secretscanAttestor.allowList == nil {
					secretscanAttestor.allowList = &AllowList{
						Description: "Witness secretscan allowlist",
					}
				}

				// Add stop word to allowlist
				secretscanAttestor.allowList.StopWords = append(secretscanAttestor.allowList.StopWords, stopWord)
				return secretscanAttestor, nil
			},
		),
	)
}

// Documentation returns documentation for the secretscan attestor
func (a *Attestor) Documentation() attestation.Documentation {
	return attestation.Documentation{
		Summary: "Scans products and attestations for secrets and sensitive information using Gitleaks",
		Usage: []string{
			"Detect accidental secret exposure in build artifacts",
			"Enforce security policies by failing builds with secrets",
			"Scan for encoded or obfuscated sensitive data",
		},
		Example: "witness run -s scan -k key.pem -a secretscan -- go test ./...",
	}
}
