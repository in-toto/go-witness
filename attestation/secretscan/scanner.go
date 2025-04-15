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
// This file (scanner.go) contains core scanning functionality.
package secretscan

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/commandrun"
	"github.com/in-toto/go-witness/log"
	"github.com/zricethezav/gitleaks/v8/detect"
)

// scanBytes is the core scanning function that handles both direct and recursive scanning
// of content for secrets. It can decode encoded content and recursively search
// through multiple layers of encoding.
func (a *Attestor) scanBytes(contentBytes []byte, sourceIdentifier string, detector *detect.Detector, processedInThisScan map[string]struct{}, currentDepth int) ([]Finding, error) {
	// Safety check to prevent infinite recursion
	if currentDepth > maxScanRecursionDepth {
		return nil, nil
	}

	// Convert bytes to string for processing
	contentStr := string(contentBytes)

	// Initialize findings slice
	findings := []Finding{}

	// Check if content is allowlisted
	if a.configPath == "" && a.allowList != nil {
		if isContentAllowListed(contentStr, a.allowList) {
			return findings, nil
		}
	}

	// Scan current layer with Gitleaks
	gitleaksFindings := detector.DetectBytes(contentBytes)
	log.Debugf("(attestation/secretscan) gitleaks found %d raw findings at depth %d for: %s",
		len(gitleaksFindings), currentDepth, sourceIdentifier)

	// Process findings with updated helper that handles locationApproximate
	isApproximate := currentDepth > 0 // Location is approximate if we're in a decoded layer
	processedGLFindings := a.processGitleaksFindings(gitleaksFindings, sourceIdentifier, isApproximate, processedInThisScan)
	findings = append(findings, processedGLFindings...)

	// Add Env Var check only at depth 0 (avoid it for decoded content)
	if currentDepth == 0 {
		sensitiveEnvVars := a.getSensitiveEnvVarsList()
		envFindings := a.ScanForEnvVarValues(contentStr, sourceIdentifier, sensitiveEnvVars)

		// Filter env findings against already processed findings
		for _, finding := range envFindings {
			findingKey := fmt.Sprintf("%s:%d:%s", sourceIdentifier, finding.Line, finding.Secret)
			if _, exists := processedInThisScan[findingKey]; exists {
				continue
			}
			processedInThisScan[findingKey] = struct{}{}
			findings = append(findings, finding)
		}
	}

	// Recursive scanning through encoding layers if configured
	if currentDepth < a.maxDecodeLayers {
		// Apply each encoding scanner
		for _, scanner := range defaultEncodingScanners {
			// Find potential encoded strings
			candidates := scanner.Finder(contentStr)

			for _, candidate := range candidates {
				// Decode each candidate
				decodedBytes, err := scanner.Decoder(candidate)

				// Special handling for potential double-encoded values (like output from echo $TOKEN | base64 | base64)
				// For base64 encoded content especially, we want to be more permissive with length checks
				if err == nil && (len(decodedBytes) >= minSensitiveValueLength ||
					(currentDepth > 0 && len(decodedBytes) > 0) ||
					strings.HasSuffix(candidate, "=")) {
					// Trim spaces to handle newlines that might be introduced by echo commands
					decodedBytes = []byte(strings.TrimSpace(string(decodedBytes)))
					decodedStr := string(decodedBytes)

					// Check decoded content for sensitive env var values
					// This can catch encoded env values even without their variable names
					sensitiveEnvVars := a.getSensitiveEnvVarsList()
					envFindings := a.checkDecodedContentForSensitiveValues(
						decodedStr,
						sourceIdentifier,
						scanner.Name,
						sensitiveEnvVars,
						processedInThisScan,
					)

					if len(envFindings) > 0 {
						log.Debugf("(attestation/secretscan) found %d sensitive env values in decoded content at depth %d for: %s",
							len(envFindings), currentDepth, sourceIdentifier)
						findings = append(findings, envFindings...)
					}

					// Recursive call with incremented depth
					recursiveFindings, recErr := a.scanBytes(
						decodedBytes,
						sourceIdentifier,
						detector,
						processedInThisScan,
						currentDepth+1,
					)

					if recErr != nil {
						log.Debugf("(attestation/secretscan) error in recursive scan: %s", recErr)
						continue
					}

					// Update encoding path for findings
					for i := range recursiveFindings {
						// For recursive findings, we need to add the current encoding type to the path
						// The correct order is from outermost to innermost layer (the reverse of decoding order)
						// So we add the current encoder name to the beginning of the path, not the end
						// This ensures the encodingPath array matches the actual encoding order
						if len(recursiveFindings[i].EncodingPath) > 0 {
							// For existing paths, prepend the current encoding to maintain proper order
							encodingPath := append([]string{scanner.Name}, recursiveFindings[i].EncodingPath...)
							recursiveFindings[i].EncodingPath = encodingPath
						} else {
							// If there's no existing path, just set it to the current encoding
							recursiveFindings[i].EncodingPath = []string{scanner.Name}
						}
						recursiveFindings[i].LocationApproximate = true
					}

					// Add recursive findings to results
					findings = append(findings, recursiveFindings...)
				}
			}
		}
	}

	if len(findings) > 0 {
		log.Debugf("(attestation/secretscan) found %d total findings at depth %d for: %s",
			len(findings), currentDepth, sourceIdentifier)
	}

	return findings, nil
}

// ScanFile scans a single file with Gitleaks detector and filters findings based on allowlist.
// It also checks for hardcoded sensitive environment variable names.
// This method is exported for testing purposes.
func (a *Attestor) ScanFile(filePath string, detector *detect.Detector) ([]Finding, error) {
	// Verify detector is provided
	if detector == nil {
		return nil, fmt.Errorf("nil detector provided")
	}

	// Validate and check file size
	if exceeds, err := a.exceedsMaxFileSize(filePath); err != nil || exceeds {
		return nil, err // If error or exceeds size limit, return immediately
	}

	// Read file content
	content, err := a.readFileContent(filePath)
	if err != nil {
		return nil, err
	}

	// Create a map to track processed findings within this scan tree
	// This helps avoid duplicate findings in deep scanning
	processedInThisScan := make(map[string]struct{})

	// Use scanBytes as the core implementation for scanning content
	return a.scanBytes(content, filePath, detector, processedInThisScan, 0)
}

// exceedsMaxFileSize checks if a file exceeds the configured size limit
func (a *Attestor) exceedsMaxFileSize(filePath string) (bool, error) {
	// Check file size to avoid loading unnecessarily large files
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return false, fmt.Errorf("error getting file info: %w", err)
	}

	// Apply size limit if configured (maxFileSizeMB of 0 means no limit)
	maxSizeBytes := int64(a.maxFileSizeMB) * 1024 * 1024
	if a.maxFileSizeMB > 0 && fileInfo.Size() > maxSizeBytes {
		log.Debugf("(attestation/secretscan) skipping large file: %s (size: %d bytes, max: %d bytes)",
			filePath, fileInfo.Size(), maxSizeBytes)
		return true, nil
	}

	return false, nil
}

// readFileContent reads file content with size limiting
func (a *Attestor) readFileContent(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Debugf("(attestation/secretscan) error closing file: %s", err)
		}
	}()

	// Apply the size limit for safety
	maxSizeBytes := int64(a.maxFileSizeMB) * 1024 * 1024
	reader := io.LimitReader(file, maxSizeBytes)

	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return content, nil
}

// scanAttestations examines all completed attestors for potential secrets.
// Each attestor is converted to JSON and scanned with the detector.
func (a *Attestor) scanAttestations(ctx *attestation.AttestationContext, tempDir string, detector *detect.Detector) error {
	// Get all completed attestors
	completedAttestors := ctx.CompletedAttestors()
	log.Debugf("(attestation/secretscan) scanning %d completed attestors", len(completedAttestors))

	// Process each attestor
	for _, completed := range completedAttestors {
		// Skip attestors that should not be scanned
		if a.shouldSkipAttestor(completed.Attestor) {
			continue
		}

		// Scan the attestor for secrets
		findings, err := a.scanSingleAttestor(completed.Attestor, tempDir, detector)
		if err != nil {
			log.Debugf("(attestation/secretscan) error scanning attestor %s: %s", completed.Attestor.Name(), err)
			continue
		}

		// Set location for all findings to identify which attestor they came from
		a.setAttestationLocation(findings, completed.Attestor.Name())

		// Add the findings to our collection
		a.Findings = append(a.Findings, findings...)
	}

	return nil
}

// shouldSkipAttestor determines if an attestor should be skipped during scanning
func (a *Attestor) shouldSkipAttestor(attestor attestation.Attestor) bool {
	// Skip scanning ourselves to avoid recursion
	if attestor.Name() == Name {
		return true
	}

	// Skip other post-product attestors to avoid race conditions
	if attestor.RunType() == RunType {
		log.Debugf("(attestation/secretscan) skipping other post-product attestor: %s", attestor.Name())
		return true
	}

	return false
}

// scanSingleAttestor converts an attestor to JSON and scans it for secrets
func (a *Attestor) scanSingleAttestor(attestor attestation.Attestor, tempDir string, detector *detect.Detector) ([]Finding, error) {
	// Check for commandrun attestor specifically to access stdout/stderr
	if cmdRunAttestor, ok := attestor.(commandrun.CommandRunAttestor); ok {
		return a.scanCommandRunAttestor(cmdRunAttestor, detector)
	}

	// For other attestors, convert to JSON for scanning
	attestorJSON, err := json.MarshalIndent(attestor, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("error marshaling attestor %s: %w", attestor.Name(), err)
	}

	// Create a unique identifier for the source
	sourceIdentifier := fmt.Sprintf("attestation_%s.json", attestor.Name())

	// Create a map to track processed findings within this scan tree
	processedInThisScan := make(map[string]struct{})

	// Scan the JSON bytes directly without creating a temporary file
	return a.scanBytes(attestorJSON, sourceIdentifier, detector, processedInThisScan, 0)
}

// scanCommandRunAttestor specifically handles scanning the stdout/stderr of command run attestors
func (a *Attestor) scanCommandRunAttestor(attestor commandrun.CommandRunAttestor, detector *detect.Detector) ([]Finding, error) {
	// Access the CommandRun data
	cmdData := attestor.Data()
	if cmdData == nil {
		return nil, fmt.Errorf("nil CommandRun data")
	}

	cmdRun := cmdData

	findings := []Finding{}

	// Scan stdout if present
	if cmdRun.Stdout != "" {
		processedInThisScan := make(map[string]struct{})
		stdoutID := "attestation:commandrun:stdout"
		stdoutFindings, err := a.scanBytes([]byte(cmdRun.Stdout), stdoutID, detector, processedInThisScan, 0)
		if err != nil {
			log.Debugf("(attestation/secretscan) error scanning command stdout: %s", err)
		} else {
			findings = append(findings, stdoutFindings...)
		}
	}

	// Scan stderr if present
	if cmdRun.Stderr != "" {
		processedInThisScan := make(map[string]struct{})
		stderrID := "attestation:commandrun:stderr"
		stderrFindings, err := a.scanBytes([]byte(cmdRun.Stderr), stderrID, detector, processedInThisScan, 0)
		if err != nil {
			log.Debugf("(attestation/secretscan) error scanning command stderr: %s", err)
		} else {
			findings = append(findings, stderrFindings...)
		}
	}

	// Also scan the JSON representation of the command run data
	cmdRunJSON, err := json.MarshalIndent(cmdRun, "", "  ")
	if err != nil {
		log.Debugf("(attestation/secretscan) error marshaling command run data: %s", err)
	} else {
		processedInThisScan := make(map[string]struct{})
		cmdRunID := "attestation:commandrun:json"
		cmdRunFindings, err := a.scanBytes(cmdRunJSON, cmdRunID, detector, processedInThisScan, 0)
		if err != nil {
			log.Debugf("(attestation/secretscan) error scanning command run JSON: %s", err)
		} else {
			findings = append(findings, cmdRunFindings...)
		}
	}

	return findings, nil
}

// scanProducts examines all products for potential secrets.
// Binary files and directories are automatically skipped.
func (a *Attestor) scanProducts(ctx *attestation.AttestationContext, tempDir string, detector *detect.Detector) error {
	products := ctx.Products()
	if len(products) == 0 {
		log.Debugf("(attestation/secretscan) no products found to scan")
		return nil
	}

	log.Debugf("(attestation/secretscan) scanning %d products", len(products))

	for path, product := range products {
		// Skip files that should not be scanned
		if a.shouldSkipProduct(path, product) {
			continue
		}

		// Get absolute path for scanning while preserving original path for records
		absPath := a.getAbsolutePath(path, ctx.WorkingDir())

		// Scan the file for secrets
		findings, err := a.ScanFile(absPath, detector)
		if err != nil {
			log.Debugf("(attestation/secretscan) error scanning file %s: %s", path, err)
			continue
		}

		// Set location for all findings to identify which product they came from
		a.setProductLocation(findings, path)

		// Add findings to collection (if any)
		if len(findings) > 0 { // Keep the log statement conditional
			log.Debugf("(attestation/secretscan) found %d findings in product: %s", len(findings), path)
		}
		a.Findings = append(a.Findings, findings...) // Append regardless (appending empty slice is ok)

		// Add product to subjects map using the original path format (regardless of findings)
		a.subjects[fmt.Sprintf("product:%s", path)] = product.Digest
	}

	return nil
}

// shouldSkipProduct determines if a product should be skipped during scanning
// based on its type and other characteristics
func (a *Attestor) shouldSkipProduct(path string, product attestation.Product) bool {
	// Skip directories
	if product.MimeType == "text/directory" {
		log.Debugf("(attestation/secretscan) skipping directory: %s", path)
		return true
	}

	// Skip binary files
	if isBinaryFile(product.MimeType) {
		log.Debugf("(attestation/secretscan) skipping binary file: %s (mime: %s)", path, product.MimeType)
		return true
	}

	return false
}

// getAbsolutePath converts a path to absolute if it's relative and we have a working directory
func (a *Attestor) getAbsolutePath(path, workingDir string) string {
	if !filepath.IsAbs(path) && workingDir != "" {
		absPath := filepath.Join(workingDir, path)
		log.Debugf("(attestation/secretscan) converting relative path %s to absolute path %s", path, absPath)
		return absPath
	}
	return path
}

// Attest scans attestations and products for potential secrets.
// The attestor will fail if configured with failOnDetection=true and secrets are found.
func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	// Store the attestation context for later use
	a.ctx = ctx

	// Create a temporary directory for scanning
	tempDir, err := os.MkdirTemp("", "secretscan")
	if err != nil {
		return fmt.Errorf("error creating temp dir: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			log.Debugf("(attestation/secretscan) error removing temp dir: %s", err)
		}
	}()

	// Initialize Gitleaks detector
	detector, err := a.initGitleaksDetector()
	if err != nil {
		return fmt.Errorf("error initializing gitleaks detector: %w", err)
	}

	// Scan attestations first (non-critical)
	if err := a.scanAttestations(ctx, tempDir, detector); err != nil {
		log.Debugf("(attestation/secretscan) error scanning attestations: %s", err)
	}

	// Scan products (primary objective)
	if err := a.scanProducts(ctx, tempDir, detector); err != nil {
		log.Debugf("(attestation/secretscan) error scanning products: %s", err)
	}

	// Fail if configured and secrets are found
	if a.failOnDetection && len(a.Findings) > 0 {
		return fmt.Errorf("secret scanning failed: found %d secrets", len(a.Findings))
	}

	return nil
}
