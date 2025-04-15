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
// This file (config_test.go) contains tests for configuration options.
package secretscan

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWithFailOnDetection(t *testing.T) {
	// Default should be false
	a := New()
	assert.False(t, a.failOnDetection, "Default failOnDetection should be false")

	// Test setting to true
	a = New(WithFailOnDetection(true))
	assert.True(t, a.failOnDetection, "failOnDetection should be set to true")

	// Test overriding
	a = New(WithFailOnDetection(true), WithFailOnDetection(false))
	assert.False(t, a.failOnDetection, "Last option should override previous options")
}

func TestWithMaxFileSize(t *testing.T) {
	// Default should be defaultMaxFileSizeMB
	a := New()
	assert.Equal(t, defaultMaxFileSizeMB, a.maxFileSizeMB, "Default maxFileSizeMB should be %d", defaultMaxFileSizeMB)

	// Test setting a positive value
	a = New(WithMaxFileSize(5))
	assert.Equal(t, 5, a.maxFileSizeMB, "maxFileSizeMB should be set to 5")

	// Test with a negative value (should not change from default)
	a = New(WithMaxFileSize(-1))
	assert.Equal(t, defaultMaxFileSizeMB, a.maxFileSizeMB, "maxFileSizeMB should not change for negative values")

	// Test with zero (should not change from default)
	a = New(WithMaxFileSize(0))
	assert.Equal(t, defaultMaxFileSizeMB, a.maxFileSizeMB, "maxFileSizeMB should not change for zero value")
}

func TestWithFilePermissions(t *testing.T) {
	// Default should be defaultFilePerm
	a := New()
	assert.Equal(t, os.FileMode(defaultFilePerm), a.filePerm, "Default filePerm should be %o", defaultFilePerm)

	// Test setting to a different value
	a = New(WithFilePermissions(0644))
	assert.Equal(t, os.FileMode(0644), a.filePerm, "filePerm should be set to 0644")
}

func TestWithAllowList(t *testing.T) {
	// Default should be nil
	a := New()
	assert.Nil(t, a.allowList, "Default allowList should be nil")

	// Test setting to a non-nil value
	allowList := &AllowList{
		Description: "Test allowlist",
		Regexes:     []string{"test.*"},
		StopWords:   []string{"secret"},
	}
	a = New(WithAllowList(allowList))
	assert.Equal(t, allowList, a.allowList, "allowList should be set to the provided value")
	assert.Equal(t, "Test allowlist", a.allowList.Description, "allowList description should match")
	assert.Equal(t, []string{"test.*"}, a.allowList.Regexes, "allowList regexes should match")
	assert.Equal(t, []string{"secret"}, a.allowList.StopWords, "allowList stopwords should match")
}

func TestWithConfigPath(t *testing.T) {
	// Default should be empty
	a := New()
	assert.Equal(t, defaultConfigPath, a.configPath, "Default configPath should be empty")

	// Test setting to a non-empty value
	a = New(WithConfigPath("/path/to/config.toml"))
	assert.Equal(t, "/path/to/config.toml", a.configPath, "configPath should be set to the provided value")
}

func TestWithMaxDecodeLayers(t *testing.T) {
	// Default should be defaultMaxDecodeLayers
	a := New()
	assert.Equal(t, defaultMaxDecodeLayers, a.maxDecodeLayers, "Default maxDecodeLayers should be %d", defaultMaxDecodeLayers)

	// Test setting a positive value
	a = New(WithMaxDecodeLayers(3))
	assert.Equal(t, 3, a.maxDecodeLayers, "maxDecodeLayers should be set to 3")

	// Test with a negative value (should not change from default)
	a = New(WithMaxDecodeLayers(-1))
	assert.Equal(t, defaultMaxDecodeLayers, a.maxDecodeLayers, "maxDecodeLayers should not change for negative values")

	// Test with zero (should be set to zero - valid value for disabling decoding)
	a = New(WithMaxDecodeLayers(0))
	assert.Equal(t, 0, a.maxDecodeLayers, "maxDecodeLayers should be set to 0")
}

func TestNew(t *testing.T) {
	// Test default values
	a := New()
	assert.Equal(t, defaultFailOnDetection, a.failOnDetection, "Default failOnDetection should be %v", defaultFailOnDetection)
	assert.Equal(t, defaultMaxFileSizeMB, a.maxFileSizeMB, "Default maxFileSizeMB should be %d", defaultMaxFileSizeMB)
	assert.Equal(t, os.FileMode(defaultFilePerm), a.filePerm, "Default filePerm should be %o", defaultFilePerm)
	assert.Nil(t, a.allowList, "Default allowList should be nil")
	assert.Equal(t, defaultConfigPath, a.configPath, "Default configPath should be empty")
	assert.Equal(t, defaultMaxDecodeLayers, a.maxDecodeLayers, "Default maxDecodeLayers should be %d", defaultMaxDecodeLayers)
	assert.NotNil(t, a.subjects, "Subjects map should be initialized")
	assert.Equal(t, 0, len(a.subjects), "Subjects map should be empty")

	// Test setting multiple options
	a = New(
		WithFailOnDetection(true),
		WithMaxFileSize(5),
		WithFilePermissions(0644),
		WithAllowList(&AllowList{Description: "Test"}),
		WithConfigPath("/path/to/config.toml"),
		WithMaxDecodeLayers(3),
	)
	assert.True(t, a.failOnDetection, "failOnDetection should be set to true")
	assert.Equal(t, 5, a.maxFileSizeMB, "maxFileSizeMB should be set to 5")
	assert.Equal(t, os.FileMode(0644), a.filePerm, "filePerm should be set to 0644")
	assert.NotNil(t, a.allowList, "allowList should be set")
	assert.Equal(t, "Test", a.allowList.Description, "allowList description should match")
	assert.Equal(t, "/path/to/config.toml", a.configPath, "configPath should be set")
	assert.Equal(t, 3, a.maxDecodeLayers, "maxDecodeLayers should be set to 3")
}

func TestAttestorInterface(t *testing.T) {
	a := New()
	assert.Equal(t, Name, a.Name(), "Name() should return the constant Name")
	assert.Equal(t, Type, a.Type(), "Type() should return the constant Type")
	assert.Equal(t, RunType, a.RunType(), "RunType() should return the constant RunType")
	assert.NotNil(t, a.Schema(), "Schema() should return a non-nil schema")
}

func TestSubjects(t *testing.T) {
	a := New()
	assert.Empty(t, a.Subjects(), "Initial subjects should be empty")

	// Test adding subjects
	a.subjects["test"] = nil
	assert.Equal(t, 1, len(a.Subjects()), "Subjects() should return map with one entry")
	assert.Contains(t, a.Subjects(), "test", "Subjects() should contain the added key")
}
