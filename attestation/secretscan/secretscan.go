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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/registry"
	"github.com/invopop/jsonschema"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

const (
	Name    = "secretscan"
	Type    = "https://witness.dev/attestations/secretscan/v0.1"
	RunType = attestation.PostProductRunType

	// Default configuration values
	defaultFailOnDetection = false
	defaultMaxFileSizeMB   = 10   // Default maximum file size to scan (in MB)
	defaultFilePerm        = 0600 // More restrictive file permissions (owner read/write only)
	defaultAllowList       = ""   // No default allow list
	defaultConfigPath      = ""   // No default custom config path
)

// Verify the Attestor implements the required interfaces at compile time.
var (
	_ attestation.Attestor  = &Attestor{} // Ensures Attestor implements Attestor interface
	_ attestation.Subjecter = &Attestor{} // Ensures Attestor implements Subjecter interface
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor { return New() },
		// Configure whether to fail when secrets are detected
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
		// Configure maximum file size to scan
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
		// Configure custom Gitleaks config file path
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

		// Configure allowlist regexes
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

		// Configure allowlist stop words
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

type Option func(*Attestor)

// WithFailOnDetection configures the attestor to fail when secrets are detected
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
func WithAllowList(allowList *AllowList) Option {
	return func(a *Attestor) {
		a.allowList = allowList
	}
}

// WithConfigPath sets a custom Gitleaks configuration file path
func WithConfigPath(configPath string) Option {
	return func(a *Attestor) {
		a.configPath = configPath
	}
}

// Finding represents a detected secret with sensitive data properly obfuscated.
// It stores details about the detected secret while ensuring the actual secret
// is not exposed.
type Finding struct {
	// RuleID is the ID of the detection rule that found this secret
	RuleID string `json:"ruleId"`

	// Description explains what type of secret was found
	Description string `json:"description"`

	// File is the path to the file containing the secret
	File string `json:"file"`

	// Line is the line number where the secret was found
	Line int `json:"startLine"`

	// Secret holds an obfuscated representation of the secret:
	// Format: rule_id:prefix...:SHA256:hash
	// Example: aws-key:AKI...:SHA256:a1b2c3d4...
	Secret string `json:"secret,omitempty"`

	// Match contains a truncated snippet showing context around the secret
	Match string `json:"match,omitempty"`

	// Entropy represents the information density (if calculated)
	Entropy float32 `json:"entropy,omitempty"`

	// Source identifies where this finding came from (attestation, product)
	// Format: product:/path/to/file or attestation:attestor-name
	Source string `json:"source"`
}

// AllowList defines patterns that should be ignored during secret scanning.
// This reduces false positives and allows expected patterns to be permitted.
type AllowList struct {
	// Description explains the purpose of this allowlist
	Description string `json:"description,omitempty"`

	// Paths are file path patterns to ignore (regex format)
	Paths []string `json:"paths,omitempty"`

	// Regexes are content patterns to ignore (regex format)
	Regexes []string `json:"regexes,omitempty"`

	// StopWords are specific strings to ignore (exact match)
	StopWords []string `json:"stopWords,omitempty"`
}

// Attestor performs scanning of products and attestations for potential secrets
// using Gitleaks detection rules. It implements the attestation.Attestor interface
// and provides these key security features:
//
//  1. Secret Obfuscation: Detected secrets are hashed with SHA256 with only a small
//     prefix retained for identification
//
// 2. File Filtering: Binary files and directories are automatically skipped
//
// 3. Size Limiting: Large files are skipped to prevent resource exhaustion
//
// 4. Allowlisting: Supports ignoring specific paths, patterns, or stopwords
//
// 5. Configurable Behavior: Can report findings or fail the attestation process
//
// The attestor runs after product attestors to analyze all products and adds
// scanned products as subjects for verifiability.
type Attestor struct {
	// Configuration options
	failOnDetection bool
	maxFileSizeMB   int
	filePerm        os.FileMode
	allowList       *AllowList
	configPath      string

	// Results and state
	Findings []Finding `json:"findings"`
	subjects map[string]cryptoutil.DigestSet
}

func New(opts ...Option) *Attestor {
	a := &Attestor{
		failOnDetection: defaultFailOnDetection,
		maxFileSizeMB:   defaultMaxFileSizeMB,
		filePerm:        defaultFilePerm,
		allowList:       nil,
		configPath:      defaultConfigPath,
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

// Attest scans attestations and products for potential secrets.
// The attestor will fail if configured with failOnDetection=true and secrets are found.
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

// initGitleaksDetector creates and configures a Gitleaks detector.
// Custom configuration file support can be added in the future.
func (a *Attestor) initGitleaksDetector() (*detect.Detector, error) {
	// Log if custom config path is provided but not yet implemented
	if a.configPath != "" {
		// TODO: Add support for custom Gitleaks configuration files
		log.Debugf("(attestation/secretscan) custom config path not implemented, using default")
	}

	// Use Gitleaks' default configuration which has comprehensive rules
	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("error creating gitleaks detector: %w", err)
	}

	// Apply file size limit configuration
	if a.maxFileSizeMB > 0 {
		detector.MaxTargetMegaBytes = a.maxFileSizeMB
	}

	return detector, nil
}

// scanAttestations examines all completed attestors for potential secrets.
// Each attestor is converted to JSON and scanned with the detector.
func (a *Attestor) scanAttestations(ctx *attestation.AttestationContext, tempDir string, detector *detect.Detector) error {
	// Get all completed attestors
	completedAttestors := ctx.CompletedAttestors()
	log.Debugf("(attestation/secretscan) scanning %d completed attestors", len(completedAttestors))

	for _, completed := range completedAttestors {
		// Skip scanning ourselves to avoid recursion
		if completed.Attestor.Name() == Name {
			continue
		}

		// Convert attestor to JSON for scanning
		attestorJSON, err := json.MarshalIndent(completed.Attestor, "", "  ")
		if err != nil {
			log.Debugf("(attestation/secretscan) error marshaling attestor %s: %s", completed.Attestor.Name(), err)
			continue
		}

		// Create a temporary file with restrictive permissions
		filename := filepath.Join(tempDir, fmt.Sprintf("attestor_%s.json", completed.Attestor.Name()))
		if err := os.WriteFile(filename, attestorJSON, a.filePerm); err != nil {
			log.Debugf("(attestation/secretscan) error writing temp file: %s", err)
			continue
		}

		// Scan the file
		findings, err := a.ScanFile(filename, detector)
		if err != nil {
			log.Debugf("(attestation/secretscan) error scanning attestor %s: %s", completed.Attestor.Name(), err)
			continue
		}

		// Mark the source of these findings
		for i := range findings {
			findings[i].Source = fmt.Sprintf("attestation:%s", completed.Attestor.Name())
		}

		// Add the findings - note we don't add attestations as subjects since they
		// are not subjects in the conceptual model of witnessing
		a.Findings = append(a.Findings, findings...)
	}

	return nil
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
		// Skip directories
		if product.MimeType == "text/directory" {
			log.Debugf("(attestation/secretscan) skipping directory: %s", path)
			continue
		}

		// Skip binary files
		if isBinaryFile(product.MimeType) {
			log.Debugf("(attestation/secretscan) skipping binary file: %s (mime: %s)", path, product.MimeType)
			continue
		}

		// Convert to absolute path for scanning while preserving original path for records
		absPath := path
		if !filepath.IsAbs(path) && ctx.WorkingDir() != "" {
			absPath = filepath.Join(ctx.WorkingDir(), path)
			log.Debugf("(attestation/secretscan) converting relative path %s to absolute path %s", path, absPath)
		}

		// Scan text files using absolute path to ensure file can be opened
		findings, err := a.ScanFile(absPath, detector)
		if err != nil {
			log.Debugf("(attestation/secretscan) error scanning file %s: %s", path, err)
			continue
		}

		// Record source of findings with original path (for consistency with other attestors)
		for i := range findings {
			findings[i].Source = fmt.Sprintf("product:%s", path)
		}

		// Add findings to collection
		if len(findings) > 0 {
			log.Debugf("(attestation/secretscan) found %d findings in product: %s", len(findings), path)
			a.Findings = append(a.Findings, findings...)
		}

		// Add product to subjects map using the original path format (regardless of findings)
		a.subjects[fmt.Sprintf("product:%s", path)] = product.Digest
	}

	return nil
}

// ScanFile scans a single file with Gitleaks detector and filters findings based on allowlist.
// This method is exported for testing purposes.
func (a *Attestor) ScanFile(filePath string, detector *detect.Detector) ([]Finding, error) {
	// Verify detector is provided
	if detector == nil {
		return nil, fmt.Errorf("nil detector provided")
	}

	// Check file size to avoid loading unnecessarily large files
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("error getting file info: %w", err)
	}

	// Apply size limit if configured (maxFileSizeMB of 0 means no limit)
	maxSizeBytes := int64(a.maxFileSizeMB) * 1024 * 1024
	if a.maxFileSizeMB > 0 && fileInfo.Size() > maxSizeBytes {
		log.Debugf("(attestation/secretscan) skipping large file: %s (size: %d bytes, max: %d bytes)",
			filePath, fileInfo.Size(), maxSizeBytes)
		return nil, nil
	}

	// Read file content with size limiting
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	reader := io.LimitReader(file, maxSizeBytes)
	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	// Skip files that match allowlist patterns
	contentStr := string(content)
	if a.allowList != nil && isContentAllowListed(contentStr, a.allowList) {
		log.Debugf("(attestation/secretscan) skipping allowlisted file: %s", filePath)
		return nil, nil
	}

	// Detect secrets using Gitleaks
	gitleaksFindings := detector.DetectBytes(content)
	log.Debugf("(attestation/secretscan) gitleaks found %d raw findings in file: %s", len(gitleaksFindings), filePath)

	// Process findings
	findings := []Finding{}
	for _, gf := range gitleaksFindings {
		// Skip allowlisted matches
		if a.allowList != nil && isMatchAllowlisted(gf.Match, a.allowList) {
			log.Debugf("(attestation/secretscan) allowlisted finding: %s in %s", gf.RuleID, filePath)
			continue
		}

		// Process the finding with secure formatting
		finding := createSecureFinding(gf, filePath)
		findings = append(findings, finding)
	}

	log.Debugf("(attestation/secretscan) returning %d findings after filtering for: %s",
		len(findings), filePath)
	return findings, nil
}

// createSecureFinding converts a Gitleaks finding to our secure Finding format.
// It obfuscates secrets by using a prefix and hash to avoid exposing sensitive data.
func createSecureFinding(gf report.Finding, filePath string) Finding {
	// Use lowercase rule ID
	ruleID := strings.ToLower(gf.RuleID)

	// Create truncated prefix based on secret length
	var prefix string
	if len(gf.Secret) <= 4 {
		if len(gf.Secret) > 0 {
			prefix = gf.Secret[:1] + "..."
		} else {
			prefix = "..."
		}
	} else if len(gf.Secret) <= 8 {
		prefix = gf.Secret[:2] + "..."
	} else {
		prefix = gf.Secret[:3] + "..."
	}

	// Hash the secret with SHA256
	hasher := sha256.New()
	hasher.Write([]byte(gf.Secret))
	hashHex := hex.EncodeToString(hasher.Sum(nil))

	// Format as rule_id:prefix...:SHA256:hash
	secretValue := fmt.Sprintf("%s:%s:SHA256:%s", ruleID, prefix, hashHex)

	// Truncate match string to avoid exposing full secrets
	var matchValue string
	if len(gf.Match) > 40 {
		matchValue = gf.Match[:20] + "..." + gf.Match[len(gf.Match)-20:]
	} else {
		matchValue = gf.Match
	}

	return Finding{
		RuleID:      gf.RuleID,
		Description: gf.Description,
		File:        filePath,
		Line:        gf.StartLine,
		Match:       matchValue,
		Secret:      secretValue,
		Entropy:     gf.Entropy,
	}
}

// isContentAllowListed checks if content matches any allowlist patterns.
// Returns true if content should be allowlisted (ignored).
func isContentAllowListed(content string, allowList *AllowList) bool {
	if allowList == nil {
		return false
	}

	// Check stop words first (fastest check)
	for _, stopWord := range allowList.StopWords {
		if strings.Contains(content, stopWord) {
			log.Debugf("(attestation/secretscan) content matched stop word: %s", stopWord)
			return true
		}
	}

	// Check regex patterns
	for _, pattern := range allowList.Regexes {
		re, err := regexp.Compile(pattern)
		if err != nil {
			log.Debugf("(attestation/secretscan) error compiling regex '%s': %v", pattern, err)
			continue
		}
		if re.MatchString(content) {
			log.Debugf("(attestation/secretscan) content matched regex pattern: %s", pattern)
			return true
		}
	}

	// Check path patterns
	for _, pathPattern := range allowList.Paths {
		re, err := regexp.Compile(pathPattern)
		if err != nil {
			log.Debugf("(attestation/secretscan) error compiling path pattern '%s': %v", pathPattern, err)
			continue
		}
		if re.MatchString(content) {
			log.Debugf("(attestation/secretscan) content matched path pattern: %s", pathPattern)
			return true
		}
	}

	return false
}

// isMatchAllowlisted checks if a specific finding match should be allowlisted.
// Returns true if the match should be ignored.
func isMatchAllowlisted(match string, allowList *AllowList) bool {
	if allowList == nil {
		return false
	}

	// Check stop words (faster than regex)
	for _, stopWord := range allowList.StopWords {
		if strings.Contains(match, stopWord) {
			log.Debugf("(attestation/secretscan) match containing stop word allowlisted: %s", stopWord)
			return true
		}
	}

	// Check regex patterns
	for _, pattern := range allowList.Regexes {
		re, err := regexp.Compile(pattern)
		if err != nil {
			log.Debugf("(attestation/secretscan) error compiling regex '%s': %v", pattern, err)
			continue
		}
		if re.MatchString(match) {
			log.Debugf("(attestation/secretscan) match with regex pattern allowlisted: %s", pattern)
			return true
		}
	}

	return false
}

// isBinaryFile returns true if the MIME type represents a binary file that
// should be skipped during secret scanning to avoid false positives.
func isBinaryFile(mimeType string) bool {
	// Check common binary mime type prefixes
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

	// Check executable file suffixes
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

// Subjects returns the products that were scanned as subjects.
// This allows verification that the right products were examined.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	return a.subjects
}
