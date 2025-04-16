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
	"strings"

	"github.com/in-toto/go-witness/log"
	"github.com/zricethezav/gitleaks/v8/report"
)

// processGitleaksFindings converts Gitleaks findings to secure Finding objects
// with the following enhancements:
//  1. Filters out allowlisted matches when using manual allowlist
//  2. Deduplicates findings across different layers of scanning
//  3. Securely hashes secrets instead of storing them directly
//  4. Tracks encoding information for multi-layer encoded secrets
func (a *Attestor) processGitleaksFindings(
	gitleaksFindings []report.Finding,
	filePath string,
	isApproximate bool,
	processedInThisScan map[string]struct{}) []Finding {

	findings := []Finding{}

	// Only apply manual allowlist if no custom config path is provided
	applyManualAllowlist := a.configPath == "" && a.allowList != nil

	for _, gf := range gitleaksFindings {
		// Skip allowlisted matches when using manual allowlist
		if applyManualAllowlist && isMatchAllowlisted(gf.Match, a.allowList) {
			log.Debugf("(attestation/secretscan) allowlisted finding: %s in %s", gf.RuleID, filePath)
			continue
		}

		// Deduplicate findings across scan layers using a composite key
		if processedInThisScan != nil {
			findingKey := fmt.Sprintf("%s:%s", filePath, gf.Secret)
			if _, exists := processedInThisScan[findingKey]; exists {
				log.Debugf("(attestation/secretscan) skipping duplicate finding: %s", findingKey)
				continue
			}
			processedInThisScan[findingKey] = struct{}{}
		}

		// Create a secure finding with cryptographic hashes of the secret
		finding, err := a.createSecureFinding(gf, filePath, nil, isApproximate)
		if err != nil {
			log.Debugf("(attestation/secretscan) error creating secure finding: %s", err)
			continue
		}

		findings = append(findings, finding)
	}

	if len(findings) > 0 {
		allowlistSource := "using allowlist from " + a.configPath
		if a.configPath == "" {
			allowlistSource = fmt.Sprintf("manual allowlist applied: %t", applyManualAllowlist)
		}

		log.Debugf("(attestation/secretscan) returning %d findings after filtering (%s) for: %s",
			len(findings), allowlistSource, filePath)
	}

	return findings
}

// createSecureFinding converts a Gitleaks finding to a secure Finding format
// that removes the actual secret value and replaces it with cryptographic digests
func (a *Attestor) createSecureFinding(
	gf report.Finding,
	filePath string,
	encodingPath []string,
	isApproximate bool) (Finding, error) {

	// Calculate multi-algorithm digest set for the secret
	digestSet, err := a.calculateSecretDigests(gf.Secret)
	if err != nil {
		return Finding{}, fmt.Errorf("error calculating digests for secret: %w", err)
	}

	// Create a deep copy of the encoding path to prevent shared references
	var encodingPathCopy []string
	if encodingPath != nil {
		encodingPathCopy = make([]string, len(encodingPath))
		copy(encodingPathCopy, encodingPath)
	}

	// Create a finding with the secret replaced by its digest set
	return Finding{
		RuleID:              strings.ToLower(gf.RuleID), // Normalize rule IDs to lowercase
		Description:         gf.Description,
		Location:            filePath, // Will be updated later with proper identifier
		Line:                gf.StartLine,
		Match:               truncateMatch(gf.Match), // Truncate to avoid exposing full secrets
		Secret:              digestSet,
		Entropy:             gf.Entropy,
		EncodingPath:        encodingPathCopy,
		LocationApproximate: isApproximate,
	}, nil
}

// setAttestationLocation updates the location field for findings from attestations
// Format: "attestation:<attestor-name>"
func (a *Attestor) setAttestationLocation(findings []Finding, attestorName string) {
	for i := range findings {
		findings[i].Location = fmt.Sprintf("attestation:%s", attestorName)
	}
}

// setProductLocation updates the location field for findings from products
// Format: "product:<product-path>"
func (a *Attestor) setProductLocation(findings []Finding, productPath string) {
	for i := range findings {
		findings[i].Location = fmt.Sprintf("product:%s", productPath)
	}
}
