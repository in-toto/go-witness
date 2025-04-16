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
// This file (envscan.go) handles detection of environment variable values.
package secretscan

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/gobwas/glob"
	"github.com/in-toto/go-witness/environment"
	"github.com/in-toto/go-witness/log"
)

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

// getSensitiveEnvVarsList returns a sensitive environment variables list
// that respects the user's configuration in the attestation context
func (a *Attestor) getSensitiveEnvVarsList() map[string]struct{} {
	// Start with the default list
	sensitiveEnvVars := environment.DefaultSensitiveEnvList()

	// If we have access to the attestation context, use it to respect user configuration
	if a.ctx != nil && a.ctx.EnvironmentCapturer() != nil {
		// Get all environment variables
		allEnvVars := os.Environ()

		// Use the environment capturer to filter/process environment variables
		// according to user configuration
		processedEnvVars := a.ctx.EnvironmentCapturer().Capture(allEnvVars)

		// Create a map to track which environment variables were filtered out
		processedKeys := make(map[string]struct{})
		for key := range processedEnvVars {
			processedKeys[key] = struct{}{}
		}

		// Find environment variables that were filtered out
		// These are the ones the user considers sensitive
		for _, envVar := range allEnvVars {
			parts := strings.SplitN(envVar, "=", 2)
			if len(parts) > 0 {
				key := parts[0]
				// If the key is not in the processed map, it was filtered due to being sensitive
				if _, exists := processedKeys[key]; !exists {
					sensitiveEnvVars[key] = struct{}{}
				}
			}
		}
	}

	return sensitiveEnvVars
}

// findPatternMatchesWithRedaction finds all matches for a regex pattern
// and replaces the actual match with a redaction placeholder
func (a *Attestor) findPatternMatchesWithRedaction(content, patternStr string) []matchInfo {
	// Ensure the pattern is valid before compilation
	// Safely compile the regex - if it fails, return empty results
	pattern, err := regexp.Compile(patternStr)
	if err != nil {
		log.Debugf("(attestation/secretscan) invalid regex pattern: %v", err)
		return []matchInfo{}
	}

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
		startContextIdx := startIdx - redactionMatchContextSize
		if startContextIdx < 0 {
			startContextIdx = 0
		}
		endContextIdx := endIdx + redactionMatchContextSize
		if endContextIdx > len(content) {
			endContextIdx = len(content)
		}

		// Extract the match with context - replace actual value with placeholder
		contextPrefix := content[startContextIdx:startIdx]
		contextSuffix := content[endIdx:endContextIdx]
		matchText := contextPrefix + redactedValuePlaceholder + contextSuffix

		result = append(result, matchInfo{
			lineNumber:   lineNum,
			matchContext: matchText,
		})
	}

	return result
}

// ScanForEnvVarValues scans file content for plain and encoded environment variable values
func (a *Attestor) ScanForEnvVarValues(content, filePath string, sensitiveEnvVars map[string]struct{}) []Finding {
	findings := []Finding{}
	envVars := os.Environ()

	for _, envPair := range envVars {
		parts := strings.SplitN(envPair, "=", 2)
		if len(parts) != 2 || parts[1] == "" {
			continue
		}

		key := parts[0]
		value := parts[1]

		if len(value) < minSensitiveValueLength {
			continue
		}

		if !isEnvironmentVariableSensitive(key, sensitiveEnvVars) {
			continue
		}

		// Search for plain value with safe regex handling
		patternStr := regexp.QuoteMeta(value)

		// Validate the pattern is valid even after QuoteMeta (handles invalid UTF-8)
		if _, err := regexp.Compile(patternStr); err != nil {
			log.Debugf("(attestation/secretscan) skipping invalid regex pattern for env var %s: %v", key, err)
			continue
		}

		matches := a.findPatternMatchesWithRedaction(content, patternStr)
		for _, matchInfo := range matches {
			digestSet, err := a.calculateSecretDigests(value)
			if err != nil {
				log.Debugf("(attestation/secretscan) error calculating digest for env var value %s: %s", key, err)
				continue
			}

			finding := Finding{
				RuleID:      fmt.Sprintf("witness-env-value-%s", strings.ReplaceAll(key, "_", "-")),
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

// checkDecodedContentForSensitiveValues examines decoded content for sensitive environment variable values
// This helps catch encoded sensitive values even without their variable names present
func (a *Attestor) checkDecodedContentForSensitiveValues(
	decodedContent string,
	sourceIdentifier string,
	encodingType string,
	sensitiveEnvVars map[string]struct{},
	processedInThisScan map[string]struct{},
) []Finding {
	findings := []Finding{}
	envVars := os.Environ()

	// Search for all environment variable values in the decoded content
	for _, envPair := range envVars {
		parts := strings.SplitN(envPair, "=", 2)
		if len(parts) != 2 || parts[1] == "" {
			continue
		}

		key := parts[0]
		value := parts[1]

		if len(value) < minSensitiveValueLength {
			continue
		}

		// Only check sensitive environment variables
		if !isEnvironmentVariableSensitive(key, sensitiveEnvVars) {
			continue
		}

		// Check for the value in the decoded content, considering possible newline additions
		// First check exact match
		exactMatch := strings.Contains(decodedContent, value)

		// Next check with possible trailing newline (common in echo output)
		exactMatchWithNewline := strings.Contains(decodedContent, value+"\n")

		// Also check for a partial match with the beginning of the string (at least 3 chars)
		// This catches cases where only a prefix of the token was encoded
		minPartialLength := 3
		partialMatch := false
		partialValue := ""

		if len(value) >= minPartialLength {
			// First try the most likely case with short tokens - check with newline
			// This is the most common pattern with echo output: "ghp\n"
			if strings.Contains(decodedContent, value[:minPartialLength]+"\n") {
				partialMatch = true
				partialValue = value[:minPartialLength] + "\n"
				log.Debugf("(attestation/secretscan) found partial match with newline: %q in %q",
					value[:minPartialLength]+"\n", decodedContent)
			} else {
				// Check different lengths of the prefix, starting from longer to shorter
				for prefixLen := len(value) - 1; prefixLen >= minPartialLength; prefixLen-- {
					prefix := value[:prefixLen]
					if strings.Contains(decodedContent, prefix) {
						partialMatch = true
						partialValue = prefix
						log.Debugf("(attestation/secretscan) found partial match: %s in %s", prefix, decodedContent)
						break
					}
				}
			}
		}

		// Process the match if we found any kind of match
		if exactMatch || exactMatchWithNewline || partialMatch {
			// Determine which value to use for reporting
			matchValue := value
			isPartial := false
			if exactMatchWithNewline {
				// For exact match with newline, use full value but note it had a newline
				matchValue = value
				log.Debugf("(attestation/secretscan) exact match with newline for %s", key)
			} else if !exactMatch && partialMatch {
				matchValue = partialValue
				isPartial = true
			}

			// Create a digest set for this value
			digestSet, err := a.calculateSecretDigests(matchValue)
			if err != nil {
				log.Debugf("(attestation/secretscan) error calculating digest for decoded env var value %s: %s", key, err)
				continue
			}

			// Find approximate line number and context
			// Since we're working with decoded content, this is approximate
			lines := strings.Split(decodedContent, "\n")
			lineNumber := 0
			match := fmt.Sprintf("...%s...", truncateMatch(matchValue))

			// Try to find the value in a specific line
			for i, line := range lines {
				if strings.Contains(line, matchValue) {
					lineNumber = i + 1
					// Create a redacted/truncated version of the context
					if len(line) < 40 {
						match = strings.Replace(line, matchValue, "[REDACTED]", 1)
					} else {
						valueIndex := strings.Index(line, matchValue)
						startIndex := max(0, valueIndex-10)
						endIndex := min(len(line), valueIndex+len(matchValue)+10)
						context := line[startIndex:endIndex]
						match = strings.Replace(context, matchValue, "[REDACTED]", 1)
					}
					break
				}
			}

			// Create a finding key to avoid duplicates
			partialSuffix := ""
			if isPartial {
				partialSuffix = "-partial"
			}
			findingKey := fmt.Sprintf("%s:%d:%s:%s%s", sourceIdentifier, lineNumber, key, encodingType, partialSuffix)
			if _, exists := processedInThisScan[findingKey]; exists {
				continue
			}
			processedInThisScan[findingKey] = struct{}{}

			// Create a finding for this match
			description := fmt.Sprintf("Encoded sensitive environment variable value detected: %s", key)
			if isPartial {
				description = fmt.Sprintf("Partial encoded sensitive environment variable value detected: %s", key)
			}

			finding := Finding{
				RuleID:              fmt.Sprintf("witness-encoded-env-value-%s%s", strings.ReplaceAll(key, "_", "-"), partialSuffix),
				Description:         description,
				Location:            sourceIdentifier,
				Line:                lineNumber,
				Match:               match,
				Secret:              digestSet,
				EncodingPath:        []string{encodingType},
				LocationApproximate: true,
			}

			findings = append(findings, finding)
		}
	}

	return findings
}
