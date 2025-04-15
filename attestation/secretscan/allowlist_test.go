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
// This file (allowlist_test.go) contains tests for the allowlist functionality.
package secretscan

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsAllowlisted(t *testing.T) {
	// Create a test allowlist
	allowList := &AllowList{
		Description: "Test allowlist",
		Regexes:     []string{"test-[0-9]+", "PASSWORD=[a-zA-Z0-9]*"},
		StopWords:   []string{"ALLOWTHIS", "SKIPTHIS"},
		Paths:       []string{"/test/path/.*\\.txt"},
	}

	// Test cases for stopwords
	t.Run("StopWords", func(t *testing.T) {
		// Should match stopword
		assert.True(t, isAllowlisted("This content contains ALLOWTHIS which should be allowed", allowList, "match"),
			"Should match stopword ALLOWTHIS")

		// Another stopword
		assert.True(t, isAllowlisted("This contains SKIPTHIS pattern", allowList, "match"),
			"Should match stopword SKIPTHIS")

		// No stopword match
		assert.False(t, isAllowlisted("This contains no stopwords", allowList, "match"),
			"Should not match any stopwords")
	})

	// Test cases for regexes
	t.Run("Regexes", func(t *testing.T) {
		// Should match regex
		assert.True(t, isAllowlisted("This contains test-123 pattern", allowList, "match"),
			"Should match regex test-[0-9]+")

		// Another regex
		assert.True(t, isAllowlisted("Setting PASSWORD=abc123 in config", allowList, "match"),
			"Should match regex PASSWORD=[a-zA-Z0-9]*")

		// No regex match
		assert.False(t, isAllowlisted("This contains testXYZ pattern", allowList, "match"),
			"Should not match any regexes")
	})

	// Test cases for paths (only for content type)
	t.Run("Paths", func(t *testing.T) {
		// Should match path when checkType is content
		assert.True(t, isAllowlisted("/test/path/file.txt", allowList, "content"),
			"Should match path pattern for content type")

		// Should not match path when checkType is not content
		assert.False(t, isAllowlisted("/test/path/file.txt", allowList, "match"),
			"Should not match path pattern for match type")

		// No path match
		assert.False(t, isAllowlisted("/different/path/file.txt", allowList, "content"),
			"Should not match different path")
	})

	// Test with nil allowlist
	t.Run("NilAllowList", func(t *testing.T) {
		assert.False(t, isAllowlisted("anything", nil, "content"),
			"Should not allowlist anything when allowList is nil")
	})

	// Test with invalid regex
	t.Run("InvalidRegex", func(t *testing.T) {
		invalidRegexList := &AllowList{
			Regexes: []string{"[invalid-regex-pattern"},
		}
		// Should not panic with invalid regex
		assert.False(t, isAllowlisted("test", invalidRegexList, "match"),
			"Should not panic and return false for invalid regex")
	})
}

func TestIsContentAllowListed(t *testing.T) {
	// This is a simple wrapper around isAllowlisted, so we just verify it calls through correctly
	allowList := &AllowList{
		StopWords: []string{"ALLOWTHIS"},
	}

	assert.True(t, isContentAllowListed("ALLOWTHIS in content", allowList),
		"isContentAllowListed should return true for matching content")

	assert.False(t, isContentAllowListed("No match here", allowList),
		"isContentAllowListed should return false for non-matching content")
}

func TestIsMatchAllowlisted(t *testing.T) {
	// This is a simple wrapper around isAllowlisted, so we just verify it calls through correctly
	allowList := &AllowList{
		StopWords: []string{"ALLOWTHIS"},
	}

	assert.True(t, isMatchAllowlisted("ALLOWTHIS in match", allowList),
		"isMatchAllowlisted should return true for matching content")

	assert.False(t, isMatchAllowlisted("No match here", allowList),
		"isMatchAllowlisted should return false for non-matching content")
}

func TestIsFileContentAllowListed(t *testing.T) {
	// Create an attestor with a manual allowlist
	allowList := &AllowList{
		Description: "Test allowlist",
		StopWords:   []string{"ALLOWTHIS"},
	}

	// Test with manual allowlist and no config path
	t.Run("ManualAllowlistNoConfigPath", func(t *testing.T) {
		attestor := New(WithAllowList(allowList))
		assert.True(t, attestor.isFileContentAllowListed("ALLOWTHIS in content", "test-file.txt"),
			"Should allowlist content matching manual allowlist when no config path")

		assert.False(t, attestor.isFileContentAllowListed("No match here", "test-file.txt"),
			"Should not allowlist content not matching manual allowlist")
	})

	// Test with manual allowlist but with config path (manual list should be ignored)
	t.Run("ManualAllowlistWithConfigPath", func(t *testing.T) {
		attestor := New(WithAllowList(allowList), WithConfigPath("/path/to/config.toml"))
		assert.False(t, attestor.isFileContentAllowListed("ALLOWTHIS in content", "test-file.txt"),
			"Should not allowlist content when config path is set, even if it matches manual allowlist")
	})

	// Test with nil allowlist
	t.Run("NilAllowList", func(t *testing.T) {
		attestor := New() // No allowlist
		assert.False(t, attestor.isFileContentAllowListed("ALLOWTHIS in content", "test-file.txt"),
			"Should not allowlist content when allowlist is nil")
	})
}
