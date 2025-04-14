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
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gobwas/glob"
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/environment"
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

	// Location identifies where the secret was found
	// Format: "attestation:attestor-name" or "product:/path/to/file"
	Location string `json:"location"`

	// Line is the line number where the secret was found
	Line int `json:"startLine"`

	// Secret holds the digest set with multiple hashes of the detected secret
	// This allows for verification without exposing the actual secret
	Secret cryptoutil.DigestSet `json:"secret,omitempty"`

	// Match contains a truncated snippet showing context around the secret
	Match string `json:"match,omitempty"`

	// Entropy represents the information density (if calculated)
	Entropy float32 `json:"entropy,omitempty"`
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

// Note: SanitizationReport and FindingDetail types have been removed
// as they are redundant with the Finding type and don't provide additional value

// Attestor performs scanning of products and attestations for potential secrets
// using Gitleaks detection rules. It implements the attestation.Attestor interface
// and provides these key security features:
//
//  1. Secret Obfuscation: Detected secrets are hashed using configured digest algorithms
//     so the actual secret is never stored
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

	// Reference to the attestation context for access to hash algorithms
	ctx *attestation.AttestationContext
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
	// Convert attestor to JSON for scanning
	attestorJSON, err := json.MarshalIndent(attestor, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("error marshaling attestor %s: %w", attestor.Name(), err)
	}

	// Create a temporary file with restrictive permissions
	filename := filepath.Join(tempDir, fmt.Sprintf("attestor_%s.json", attestor.Name()))
	if err := os.WriteFile(filename, attestorJSON, a.filePerm); err != nil {
		return nil, fmt.Errorf("error writing temp file: %w", err)
	}

	// Scan the file for secrets
	return a.ScanFile(filename, detector)
}

// setAttestationLocation sets the location field on findings to the attestation name
func (a *Attestor) setAttestationLocation(findings []Finding, attestorName string) {
	for i := range findings {
		findings[i].Location = fmt.Sprintf("attestation:%s", attestorName)
	}
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

// setProductLocation sets the location field on findings to the product path
func (a *Attestor) setProductLocation(findings []Finding, productPath string) {
	for i := range findings {
		findings[i].Location = fmt.Sprintf("product:%s", productPath)
	}
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

	// Check if content is allowlisted
	contentStr := string(content)
	if a.isFileContentAllowListed(contentStr, filePath) {
		return nil, nil
	}

	// Detect secrets using Gitleaks
	gitleaksFindings := detector.DetectBytes(content)
	log.Debugf("(attestation/secretscan) gitleaks found %d raw findings in file: %s",
		len(gitleaksFindings), filePath)

	// Process gitleaks findings
	findings := a.processGitleaksFindings(gitleaksFindings, filePath)

	// Check for environment variable names
	envFindings := a.scanForEnvVarNames(contentStr, filePath)
	if len(envFindings) > 0 {
		log.Debugf("(attestation/secretscan) found %d environment variable references in file: %s",
			len(envFindings), filePath)
		findings = append(findings, envFindings...)
	}

	return findings, nil
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

// isFileContentAllowListed checks if file content matches allowlist patterns
func (a *Attestor) isFileContentAllowListed(content, filePath string) bool {
	if a.allowList != nil && isContentAllowListed(content, a.allowList) {
		log.Debugf("(attestation/secretscan) skipping allowlisted file: %s", filePath)
		return true
	}
	return false
}

// processGitleaksFindings converts Gitleaks findings to our Finding format
// and filters out any allowlisted matches
func (a *Attestor) processGitleaksFindings(gitleaksFindings []report.Finding, filePath string) []Finding {
	findings := []Finding{}

	for _, gf := range gitleaksFindings {
		// Skip allowlisted matches
		if a.allowList != nil && isMatchAllowlisted(gf.Match, a.allowList) {
			log.Debugf("(attestation/secretscan) allowlisted finding: %s in %s", gf.RuleID, filePath)
			continue
		}

		// Process the finding with secure hash
		finding, err := a.createSecureFinding(gf, filePath)
		if err != nil {
			log.Debugf("(attestation/secretscan) error creating secure finding: %s", err)
			continue
		}

		findings = append(findings, finding)
	}

	log.Debugf("(attestation/secretscan) returning %d findings after filtering for: %s",
		len(findings), filePath)
	return findings
}

// createSecureFinding converts a Gitleaks finding to our secure Finding format.
// It obfuscates secrets by securely hashing them with user-configured digest algorithms.
func (a *Attestor) createSecureFinding(gf report.Finding, filePath string) (Finding, error) {
	// Calculate digest set for the secret using configured hash algorithms
	digestSet, err := a.calculateSecretDigests(gf.Secret)
	if err != nil {
		return Finding{}, fmt.Errorf("error calculating digests for secret: %w", err)
	}

	// The Location field initially contains the temporary file path
	// but will be updated to contain the proper identifier
	return Finding{
		RuleID:      strings.ToLower(gf.RuleID), // Use lowercase rule ID
		Description: gf.Description,
		Location:    filePath,
		Line:        gf.StartLine,
		Match:       truncateMatch(gf.Match),
		Secret:      digestSet,
		Entropy:     gf.Entropy,
	}, nil
}

// truncateMatch safely truncates the match string to avoid exposing full secrets
func truncateMatch(match string) string {
	if len(match) > 40 {
		return match[:20] + "..." + match[len(match)-20:]
	}
	return match
}

// calculateSecretDigests creates a digest set for a secret using the configured digest algorithms
// from the attestation context
func (a *Attestor) calculateSecretDigests(secret string) (cryptoutil.DigestSet, error) {
	// Default hashes if context is missing (mainly for tests)
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}

	// Get hashes from context if available
	if a.ctx != nil {
		hashes = a.ctx.Hashes()
	}

	// Calculate digests for the secret
	digestSet, err := cryptoutil.CalculateDigestSetFromBytes([]byte(secret), hashes)
	if err != nil {
		return nil, fmt.Errorf("error calculating digest for secret: %w", err)
	}

	return digestSet, nil
}

// isAllowlisted is a generic function to check if a string matches allowlist patterns.
// The type parameter indicates whether checking content or a specific match.
func isAllowlisted(s string, allowList *AllowList, checkType string) bool {
	if allowList == nil {
		return false
	}

	// Check stop words first (fastest check)
	for _, stopWord := range allowList.StopWords {
		if strings.Contains(s, stopWord) {
			log.Debugf("(attestation/secretscan) %s matched stop word: %s", checkType, stopWord)
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
		if re.MatchString(s) {
			log.Debugf("(attestation/secretscan) %s matched regex pattern: %s", checkType, pattern)
			return true
		}
	}

	// Check path patterns (only for content, not for matches)
	if checkType == "content" {
		for _, pathPattern := range allowList.Paths {
			re, err := regexp.Compile(pathPattern)
			if err != nil {
				log.Debugf("(attestation/secretscan) error compiling path pattern '%s': %v", pathPattern, err)
				continue
			}
			if re.MatchString(s) {
				log.Debugf("(attestation/secretscan) content matched path pattern: %s", pathPattern)
				return true
			}
		}
	}

	return false
}

// isContentAllowListed checks if content matches any allowlist patterns.
// Returns true if content should be allowlisted (ignored).
func isContentAllowListed(content string, allowList *AllowList) bool {
	return isAllowlisted(content, allowList, "content")
}

// isMatchAllowlisted checks if a specific finding match should be allowlisted.
// Returns true if the match should be ignored.
func isMatchAllowlisted(match string, allowList *AllowList) bool {
	return isAllowlisted(match, allowList, "match")
}

// scanForEnvVarNames scans content for both:
// 1. Hardcoded sensitive environment variable names
// 2. Actual values of sensitive environment variables that are set in the system
func (a *Attestor) scanForEnvVarNames(content, filePath string) []Finding {
	findings := []Finding{}

	// Get the sensitive environment variables list
	sensitiveEnvVars := environment.DefaultSensitiveEnvList()

	// Step 1: Check for hardcoded environment variable *names*
	nameFindings := a.scanForEnvVarNamesOnly(content, filePath, sensitiveEnvVars)
	findings = append(findings, nameFindings...)

	// Step 2: Check for actual environment variable *values* that are set in the system
	valueFindings := a.scanForEnvVarValues(content, filePath, sensitiveEnvVars)
	findings = append(findings, valueFindings...)

	return findings
}

// scanForEnvVarNamesOnly checks for hardcoded references to sensitive environment variable names
func (a *Attestor) scanForEnvVarNamesOnly(content, filePath string, sensitiveEnvVars map[string]struct{}) []Finding {
	findings := []Finding{}

	// Check each environment variable name in the content
	for envVar := range sensitiveEnvVars {
		// Skip glob patterns - we can't match them directly
		if strings.Contains(envVar, "*") {
			continue
		}

		// Look for the environment variable name as a word boundary
		pattern := fmt.Sprintf(`\b%s\b`, regexp.QuoteMeta(envVar))
		matches := a.findPatternMatches(content, pattern)

		for _, matchInfo := range matches {
			// Calculate digest for the environment variable name
			digestSet, err := a.calculateSecretDigests(envVar)
			if err != nil {
				log.Debugf("(attestation/secretscan) error calculating digest for env var %s: %s", envVar, err)
				continue
			}

			// Create a finding
			finding := Finding{
				RuleID:      fmt.Sprintf("witness-env-var-%s", strings.ToLower(strings.ReplaceAll(envVar, "_", "-"))),
				Description: fmt.Sprintf("Sensitive environment variable name: %s", envVar),
				Location:    filePath,
				Line:        matchInfo.lineNumber,
				Match:       truncateMatch(matchInfo.matchContext),
				Secret:      digestSet,
			}

			findings = append(findings, finding)
		}
	}

	return findings
}

// matchInfo holds information about a pattern match in content
type matchInfo struct {
	lineNumber   int
	matchContext string
}

// findPatternMatches finds all matches for a regex pattern in content
// and returns information about each match
func (a *Attestor) findPatternMatches(content, patternStr string) []matchInfo {
	pattern := regexp.MustCompile(patternStr)
	matches := pattern.FindAllStringIndex(content, -1)
	result := []matchInfo{}

	for _, match := range matches {
		// Get line number for this occurrence
		lines := strings.Split(content[:match[0]], "\n")
		lineNum := len(lines)

		// Extract surrounding context
		startIdx := match[0]
		endIdx := match[1]

		// Get some context before and after the match
		startContextIdx := startIdx - 10
		if startContextIdx < 0 {
			startContextIdx = 0
		}
		endContextIdx := endIdx + 10
		if endContextIdx > len(content) {
			endContextIdx = len(content)
		}

		// Extract the match with context
		matchText := content[startContextIdx:endContextIdx]

		result = append(result, matchInfo{
			lineNumber:   lineNum,
			matchContext: matchText,
		})
	}

	return result
}

// findPatternMatchesWithRedaction finds all matches for a regex pattern
// and replaces the actual match with a redaction placeholder
func (a *Attestor) findPatternMatchesWithRedaction(content, patternStr string) []matchInfo {
	pattern := regexp.MustCompile(patternStr)
	matches := pattern.FindAllStringIndex(content, -1)
	result := []matchInfo{}

	for _, match := range matches {
		// Get line number for this occurrence
		lines := strings.Split(content[:match[0]], "\n")
		lineNum := len(lines)

		// Extract surrounding context
		startIdx := match[0]
		endIdx := match[1]

		// Get some context before and after the match
		startContextIdx := startIdx - 5
		if startContextIdx < 0 {
			startContextIdx = 0
		}
		endContextIdx := endIdx + 5
		if endContextIdx > len(content) {
			endContextIdx = len(content)
		}

		// Extract the match with context - replace actual value with placeholder
		contextPrefix := content[startContextIdx:startIdx]
		contextSuffix := content[endIdx:endContextIdx]
		matchText := contextPrefix + "[SENSITIVE-VALUE]" + contextSuffix

		result = append(result, matchInfo{
			lineNumber:   lineNum,
			matchContext: matchText,
		})
	}

	return result
}

// isEnvironmentVariableSensitive checks if an environment variable is sensitive
// according to the sensitive environment variables list
func isEnvironmentVariableSensitive(key string, sensitiveEnvVars map[string]struct{}) bool {
	// Direct match
	if _, exists := sensitiveEnvVars[key]; exists {
		return true
	}

	// Check glob patterns
	for envVarPattern := range sensitiveEnvVars {
		if strings.Contains(envVarPattern, "*") {
			g, err := glob.Compile(envVarPattern)
			if err != nil {
				continue
			}
			if g.Match(key) {
				return true
			}
		}
	}

	return false
}

// scanForEnvVarValues checks for environment variable values that exist in the system
func (a *Attestor) scanForEnvVarValues(content, filePath string, sensitiveEnvVars map[string]struct{}) []Finding {
	findings := []Finding{}

	// Get all environment variables
	envVars := os.Environ()

	// Process each environment variable
	for _, envPair := range envVars {
		// Split into key and value
		parts := strings.SplitN(envPair, "=", 2)
		if len(parts) != 2 || parts[1] == "" {
			continue // Skip empty values
		}

		key := parts[0]
		value := parts[1]

		// Skip very short values (less than 4 chars) to reduce false positives
		if len(value) < 4 {
			continue
		}

		// Check if this is a sensitive environment variable
		if !isEnvironmentVariableSensitive(key, sensitiveEnvVars) {
			continue
		}

		// Look for exact matches to the value
		// We need to escape the value for regex special characters
		escapedValue := regexp.QuoteMeta(value)
		matches := a.findPatternMatchesWithRedaction(content, escapedValue)

		for _, matchInfo := range matches {
			// Calculate digest for the environment variable value
			digestSet, err := a.calculateSecretDigests(value)
			if err != nil {
				log.Debugf("(attestation/secretscan) error calculating digest for env var value %s: %s", key, err)
				continue
			}

			// Create a finding
			finding := Finding{
				RuleID:      fmt.Sprintf("witness-env-value-%s", strings.ToLower(strings.ReplaceAll(key, "_", "-"))),
				Description: fmt.Sprintf("Sensitive environment variable value detected: %s", key),
				Location:    filePath,
				Line:        matchInfo.lineNumber,
				Match:       truncateMatch(matchInfo.matchContext),
				Secret:      digestSet,
			}

			findings = append(findings, finding)
		}
	}

	return findings
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
