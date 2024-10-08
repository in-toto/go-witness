// Copyright 2024 The Witness Contributors
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

package lockfiles

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/in-toto/go-witness/attestation"
)

func TestAttestor_Attest(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "lockfiles_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test lockfiles
	testFiles := map[string]string{
		"Gemfile.lock":      "test content for Gemfile.lock",
		"package-lock.json": "test content for package-lock.json",
	}

	for filename, content := range testFiles {
		err := os.WriteFile(filepath.Join(tempDir, filename), []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", filename, err)
		}
	}

	// Change to the temp directory
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}
	defer func() {
		if err := os.Chdir(oldWd); err != nil {
			t.Errorf("Failed to change back to original directory: %v", err)
		}
	}()

	err = os.Chdir(tempDir)
	if err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}

	// Create an Attestor and AttestationContext
	attestor := &Attestor{}
	ctx := &attestation.AttestationContext{}

	// Run the Attest method
	err = attestor.Attest(ctx)
	if err != nil {
		t.Fatalf("Attest failed: %v", err)
	}

	// Check if the lockfiles were captured correctly
	if len(attestor.Lockfiles) != len(testFiles) {
		t.Errorf("Expected %d lockfiles, but got %d", len(testFiles), len(attestor.Lockfiles))
	}

	for _, lockfile := range attestor.Lockfiles {
		expectedContent, ok := testFiles[lockfile.Filename]
		if !ok {
			t.Errorf("Unexpected lockfile %s found in attestation", lockfile.Filename)
		} else if lockfile.Content != expectedContent {
			t.Errorf("Lockfile %s content mismatch. Got %s, want %s", lockfile.Filename, lockfile.Content, expectedContent)
		}
		delete(testFiles, lockfile.Filename)
	}

	if len(testFiles) > 0 {
		for filename := range testFiles {
			t.Errorf("Expected lockfile %s not found in attestation", filename)
		}
	}
}

func TestAttestor_Name(t *testing.T) {
	attestor := &Attestor{}
	if name := attestor.Name(); name != "lockfiles" {
		t.Errorf("Incorrect attestor name. Got %s, want lockfiles", name)
	}
}
