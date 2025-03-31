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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/registry"
	"github.com/invopop/jsonschema"
	"github.com/zricethezav/gitleaks/v8/detect"
)

const (
	Name    = "secretscan"
	Type    = "https://witness.dev/attestations/secretscan/v0.1"
	RunType = attestation.PostProductRunType

	defaultScanBinaries    = false
	defaultFailOnDetection = false
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor { return New() },
		registry.BoolConfigOption(
			"scan-binaries",
			"Include binary files in secret scanning",
			defaultScanBinaries,
			func(a attestation.Attestor, scanBinaries bool) (attestation.Attestor, error) {
				secretscanAttestor, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a secretscan attestor", a)
				}

				WithScanBinaries(scanBinaries)(secretscanAttestor)
				return secretscanAttestor, nil
			},
		),
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
	)
}

type Option func(*Attestor)

func WithScanBinaries(scanBinaries bool) Option {
	return func(a *Attestor) {
		a.scanBinaries = scanBinaries
	}
}

func WithFailOnDetection(failOnDetection bool) Option {
	return func(a *Attestor) {
		a.failOnDetection = failOnDetection
	}
}

// Finding represents a secret finding from Gitleaks
type Finding struct {
	RuleID       string  `json:"ruleId"`
	Description  string  `json:"description"`
	Severity     string  `json:"severity"`
	File         string  `json:"file"`
	Line         int     `json:"startLine"`
	Secret       string  `json:"secret,omitempty"`
	Match        string  `json:"match,omitempty"`
	Entropy      float32 `json:"entropy,omitempty"`
	Source       string  `json:"source"`       // Identifies where this finding came from (attestation, product)
	TruncatedKey bool    `json:"truncatedKey"` // Indicates if the secret was truncated for security
}

// Attestor implements the attestation.Attestor interface for secret scanning
type Attestor struct {
	scanBinaries    bool
	failOnDetection bool
	Findings        []Finding `json:"findings"`
	subjects        map[string]cryptoutil.DigestSet
}

func New(opts ...Option) *Attestor {
	a := &Attestor{
		scanBinaries:    defaultScanBinaries,
		failOnDetection: defaultFailOnDetection,
		subjects:        make(map[string]cryptoutil.DigestSet),
	}

	for _, opt := range opts {
		opt(a)
	}

	return a
}

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) Type() string {
	return Type
}

func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(a)
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	// Create a temporary directory for scanning
	tempDir, err := os.MkdirTemp("", "secretscan")
	if err != nil {
		return fmt.Errorf("error creating temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Initialize Gitleaks detector
	detector, err := a.initGitleaksDetector()
	if err != nil {
		return fmt.Errorf("error initializing gitleaks detector: %w", err)
	}

	// Scan attestations
	if err := a.scanAttestations(ctx, tempDir, detector); err != nil {
		log.Debugf("(attestation/secretscan) error scanning attestations: %s", err)
	}

	// Scan products if enabled
	if a.scanBinaries {
		if err := a.scanProducts(ctx, tempDir, detector); err != nil {
			log.Debugf("(attestation/secretscan) error scanning products: %s", err)
		}
	}

	// If configured to fail on detection and we found secrets, return an error
	if a.failOnDetection && len(a.Findings) > 0 {
		return fmt.Errorf("secret scanning failed: found %d secrets", len(a.Findings))
	}

	return nil
}

func (a *Attestor) initGitleaksDetector() (*detect.Detector, error) {
	// Create a new detector with default config
	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("error creating gitleaks detector: %w", err)
	}
	return detector, nil
}

func (a *Attestor) scanAttestations(ctx *attestation.AttestationContext, tempDir string, detector *detect.Detector) error {
	// Get all completed attestors
	completedAttestors := ctx.CompletedAttestors()

	// Process each attestor
	for _, completed := range completedAttestors {
		// Skip scanning ourselves
		if completed.Attestor.Name() == Name {
			continue
		}

		// Convert attestor to JSON for scanning
		attestorJSON, err := json.MarshalIndent(completed.Attestor, "", "  ")
		if err != nil {
			log.Debugf("(attestation/secretscan) error marshaling attestor %s: %s", completed.Attestor.Name(), err)
			continue
		}

		// Create a file for the attestor content
		filename := filepath.Join(tempDir, fmt.Sprintf("attestor_%s.json", completed.Attestor.Name()))
		if err := os.WriteFile(filename, attestorJSON, 0644); err != nil {
			log.Debugf("(attestation/secretscan) error writing temp file: %s", err)
			continue
		}

		// Scan the file with Gitleaks
		findings, err := a.ScanFile(filename, detector)
		if err != nil {
			log.Debugf("(attestation/secretscan) error scanning attestor %s: %s", completed.Attestor.Name(), err)
			continue
		}

		// Update finding source
		for i := range findings {
			findings[i].Source = fmt.Sprintf("attestation:%s", completed.Attestor.Name())
		}

		// Note: We don't add attestations as subjects since attestations are not
		// themselves subjects in the conceptual model of witnessing

		// Add the findings to our collection
		a.Findings = append(a.Findings, findings...)
	}

	return nil
}

func (a *Attestor) scanProducts(ctx *attestation.AttestationContext, tempDir string, detector *detect.Detector) error {
	products := ctx.Products()
	if len(products) == 0 {
		return fmt.Errorf("no products to scan")
	}

	for path, product := range products {
		// Skip directories
		if product.MimeType == "text/directory" {
			continue
		}

		// For binary files, extract strings first
		if isBinaryFile(product.MimeType) {
			extractedFile := filepath.Join(tempDir, fmt.Sprintf("%s.strings", filepath.Base(path)))
			if err := extractStringsFromBinary(path, extractedFile); err != nil {
				log.Debugf("(attestation/secretscan) error extracting strings from %s: %s", path, err)
				continue
			}

			// Scan the extracted strings file
			findings, err := a.ScanFile(extractedFile, detector)
			if err != nil {
				log.Debugf("(attestation/secretscan) error scanning strings from %s: %s", path, err)
				continue
			}

			// Update findings with original file path and source
			for i := range findings {
				findings[i].File = path
				findings[i].Source = fmt.Sprintf("product:%s (binary)", path)
			}

			// Add the findings
			a.Findings = append(a.Findings, findings...)
		} else {
			// For text files, scan directly
			findings, err := a.ScanFile(path, detector)
			if err != nil {
				log.Debugf("(attestation/secretscan) error scanning file %s: %s", path, err)
				continue
			}

			// Update finding source
			for i := range findings {
				findings[i].Source = fmt.Sprintf("product:%s", path)
			}

			// Add the findings
			a.Findings = append(a.Findings, findings...)
		}

		// Add product digest to subjects map
		a.subjects[fmt.Sprintf("product:%s", path)] = product.Digest
	}

	return nil
}

// ScanFile scans a single file with Gitleaks detector
// Exported for testing purposes
func (a *Attestor) ScanFile(filePath string, detector *detect.Detector) ([]Finding, error) {
	// Read the file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	// Check for nil detector
	if detector == nil {
		return nil, fmt.Errorf("nil detector provided")
	}

	// Detect secrets in file content
	gitleaksFindings := detector.DetectBytes(content)

	// Convert Gitleaks findings to our Finding type
	findings := make([]Finding, 0, len(gitleaksFindings))
	for _, gf := range gitleaksFindings {
		// For security, truncate the actual secret
		var truncatedSecret string
		if len(gf.Secret) > 8 {
			truncatedSecret = gf.Secret[:4] + "..." + gf.Secret[len(gf.Secret)-4:]
		} else if len(gf.Secret) > 0 {
			truncatedSecret = "..."
		}

		finding := Finding{
			RuleID:       gf.RuleID,
			Description:  gf.Description,
			Severity:     getDefaultSeverity(gf.RuleID),
			File:         filePath,
			Line:         gf.StartLine,
			Match:        gf.Match,
			Secret:       truncatedSecret,
			Entropy:      gf.Entropy,
			TruncatedKey: len(gf.Secret) > 0,
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

// getDefaultSeverity returns a default severity based on the rule ID
func getDefaultSeverity(ruleID string) string {
	// These are very common high-severity rule types
	highSeverityPrefixes := []string{
		"aws", "gcp", "azure", "api", "token", "key", "credential", "password",
		"secret", "private", "auth", "ssh", "cert", "jwt",
	}

	for _, prefix := range highSeverityPrefixes {
		if strings.Contains(strings.ToLower(ruleID), prefix) {
			return "HIGH"
		}
	}

	return "MEDIUM"
}

// isBinaryFile returns true if the MIME type represents a binary file
func isBinaryFile(mimeType string) bool {
	// Common binary mime types
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

	// Executable files like .exe, .dll, .so
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

// extractStringsFromBinary extracts printable strings from a binary file
func extractStringsFromBinary(binaryPath, outputPath string) error {
	// Read the binary file
	content, err := os.ReadFile(binaryPath)
	if err != nil {
		return err
	}

	// Extract ASCII strings (basic implementation)
	var stringsList []string
	var currentString []byte
	for _, b := range content {
		// ASCII printable characters
		if b >= 32 && b <= 126 {
			currentString = append(currentString, b)
		} else if len(currentString) >= 8 { // Only keep strings of reasonable length
			stringsList = append(stringsList, string(currentString))
			currentString = nil
		} else {
			currentString = nil
		}
	}
	if len(currentString) >= 8 {
		stringsList = append(stringsList, string(currentString))
	}

	// Write strings to output file
	return os.WriteFile(outputPath, []byte(strings.Join(stringsList, "\n")), 0644)
}

func (a *Attestor) MarshalJSON() ([]byte, error) {
	type alias Attestor
	return json.Marshal(&struct {
		*alias
		Findings []Finding `json:"findings"`
	}{
		alias:    (*alias)(a),
		Findings: a.Findings,
	})
}

func (a *Attestor) UnmarshalJSON(data []byte) error {
	type alias Attestor
	aux := &struct {
		*alias
		Findings []Finding `json:"findings"`
	}{
		alias: (*alias)(a),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	a.Findings = aux.Findings
	return nil
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	return a.subjects
}
