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
	"regexp"
	"strings"

	"github.com/in-toto/go-witness/log"
)

// isAllowlisted checks if a string matches any allowlist patterns
// Parameters:
//   - s: The string to check against allowlist patterns
//   - allowList: The allowlist configuration to use
//   - checkType: The type of check being performed ("content" or "match")
//
// Returns true if the string matches any allowlist pattern and should be ignored
func isAllowlisted(s string, allowList *AllowList, checkType string) bool {
	if allowList == nil {
		return false
	}

	// Check stop words first (fastest check - simple string containment)
	for _, stopWord := range allowList.StopWords {
		if strings.Contains(s, stopWord) {
			log.Debugf("(attestation/secretscan) %s matched stop word: %s", checkType, stopWord)
			return true
		}
	}

	// Check regex patterns (more expensive but more powerful)
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

	// Check path patterns (only applicable for content checks, not individual matches)
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

// isContentAllowListed checks if content matches any allowlist patterns
// Used for checking entire files or large content blocks
// Returns true if content should be allowlisted (ignored)
func isContentAllowListed(content string, allowList *AllowList) bool {
	return isAllowlisted(content, allowList, "content")
}

// isMatchAllowlisted checks if a specific finding match should be allowlisted
// Used for checking individual finding matches after detection
// Returns true if the match should be ignored
func isMatchAllowlisted(match string, allowList *AllowList) bool {
	return isAllowlisted(match, allowList, "match")
}

// isFileContentAllowListed checks if file content matches allowlist patterns
// This method applies the attestor's configuration to determine if allowlisting
// should be applied, checking if:
// 1. No custom config file is being used (which has its own allowlist)
// 2. A manual allowlist has been configured
//
// Returns true if the content should be allowlisted (ignored)
func (a *Attestor) isFileContentAllowListed(content, filePath string) bool {
	// Only apply manual allowList checks if no config file was provided
	if a.configPath == "" && a.allowList != nil {
		if isContentAllowListed(content, a.allowList) {
			log.Debugf("(attestation/secretscan) skipping allowlisted file content: %s", filePath)
			return true
		}
	}
	return false
}
