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

// Package secretscan provides functionality for detecting secrets and sensitive information
// in code, attestations, and products. It utilizes Gitleaks for pattern matching and
// implements multi-layer encoding detection to identify obfuscated sensitive content.
// Secrets are never stored directly; instead, they are securely represented as
// cryptographic digests using multiple hash algorithms.
//
// The package is organized into these logical components:
//   - attestor.go   - Core attestor implementation
//   - config.go     - Configuration options and attestor initialization
//   - constants.go  - Package-wide constants
//   - detector.go   - Gitleaks detector configuration
//   - digest.go     - Secret digest calculation
//   - encoding.go   - Multi-layer encoding detection and decoding
//   - envscan.go    - Environment variable scanning
//   - findings.go   - Processing and securification of findings
//   - scanner.go    - Core scanning functionality
//   - types.go      - Data structures and interfaces
//   - utils.go      - Utility functions
package secretscan
