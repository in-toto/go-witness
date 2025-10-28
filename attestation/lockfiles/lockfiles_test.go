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
	"strings"
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

func TestAttestor_Attest_SpecificDirectories(t *testing.T) {
	// Create temporary directory structure
	tempDir, err := os.MkdirTemp("", "lockfiles_test_dirs")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create subdirectories
	nodeDir := filepath.Join(tempDir, "node-app")
	pythonDir := filepath.Join(tempDir, "python-app")
	if err := os.MkdirAll(nodeDir, 0755); err != nil {
		t.Fatalf("Failed to create node-app dir: %v", err)
	}
	if err := os.MkdirAll(pythonDir, 0755); err != nil {
		t.Fatalf("Failed to create python-app dir: %v", err)
	}

	// Create lockfiles in subdirectories
	nodeContent := "node lockfile content"
	pythonContent := "python lockfile content"
	if err := os.WriteFile(filepath.Join(nodeDir, "package-lock.json"), []byte(nodeContent), 0644); err != nil {
		t.Fatalf("Failed to create package-lock.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pythonDir, "requirements.txt"), []byte(pythonContent), 0644); err != nil {
		t.Fatalf("Failed to create requirements.txt: %v", err)
	}

	// Change to temp directory
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}
	defer func() {
		if err := os.Chdir(oldWd); err != nil {
			t.Errorf("Failed to change back to original directory: %v", err)
		}
	}()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}

	// Create attestor with specific directories
	attestor := &Attestor{
		SearchPaths: "node-app" + string(os.PathListSeparator) + "python-app",
	}
	ctx := &attestation.AttestationContext{}

	// Run the Attest method
	err = attestor.Attest(ctx)
	if err != nil {
		t.Fatalf("Attest failed: %v", err)
	}

	// Check if both lockfiles were found
	if len(attestor.Lockfiles) != 2 {
		t.Errorf("Expected 2 lockfiles, but got %d", len(attestor.Lockfiles))
	}

	// Verify content
	foundNode := false
	foundPython := false
	for _, lockfile := range attestor.Lockfiles {
		if filepath.Base(lockfile.Filename) == "package-lock.json" {
			if lockfile.Content != nodeContent {
				t.Errorf("package-lock.json content mismatch")
			}
			foundNode = true
		}
		if filepath.Base(lockfile.Filename) == "requirements.txt" {
			if lockfile.Content != pythonContent {
				t.Errorf("requirements.txt content mismatch")
			}
			foundPython = true
		}
	}

	if !foundNode {
		t.Error("package-lock.json not found in attestation")
	}
	if !foundPython {
		t.Error("requirements.txt not found in attestation")
	}
}

func TestAttestor_Attest_RecursiveSearch(t *testing.T) {
	// Create temporary directory structure
	tempDir, err := os.MkdirTemp("", "lockfiles_test_recursive")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create nested directory structure
	subDir1 := filepath.Join(tempDir, "app1")
	subDir2 := filepath.Join(tempDir, "app2", "nested")
	if err := os.MkdirAll(subDir1, 0755); err != nil {
		t.Fatalf("Failed to create app1 dir: %v", err)
	}
	if err := os.MkdirAll(subDir2, 0755); err != nil {
		t.Fatalf("Failed to create app2/nested dir: %v", err)
	}

	// Create lockfiles at different levels (using absolute paths for creation)
	testFilesAbs := map[string]string{
		filepath.Join(tempDir, "package-lock.json"):      "root lockfile",
		filepath.Join(subDir1, "Gemfile.lock"):           "app1 lockfile",
		filepath.Join(subDir2, "requirements.txt"):       "nested lockfile",
	}

	// Expected relative paths in attestation
	testFiles := map[string]string{
		"package-lock.json":             "root lockfile",
		"app1/Gemfile.lock":            "app1 lockfile",
		"app2/nested/requirements.txt": "nested lockfile",
	}

	for path, content := range testFilesAbs {
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create %s: %v", path, err)
		}
	}

	// Create a .git directory to test skipping hidden dirs
	gitDir := filepath.Join(tempDir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatalf("Failed to create .git dir: %v", err)
	}
	// This file should be skipped
	if err := os.WriteFile(filepath.Join(gitDir, "package-lock.json"), []byte("should be ignored"), 0644); err != nil {
		t.Fatalf("Failed to create .git/package-lock.json: %v", err)
	}

	// Change to temp directory
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}
	defer func() {
		if err := os.Chdir(oldWd); err != nil {
			t.Errorf("Failed to change back to original directory: %v", err)
		}
	}()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}

	// Create attestor with recursive search
	attestor := &Attestor{
		SearchPaths: "recursive",
	}
	ctx := &attestation.AttestationContext{}

	// Run the Attest method
	err = attestor.Attest(ctx)
	if err != nil {
		t.Fatalf("Attest failed: %v", err)
	}

	// Check if all lockfiles were found (excluding .git)
	if len(attestor.Lockfiles) != 3 {
		t.Errorf("Expected 3 lockfiles, but got %d", len(attestor.Lockfiles))
		for _, lf := range attestor.Lockfiles {
			t.Logf("Found: %s", lf.Filename)
		}
	}

	// Verify .git directory was skipped
	for _, lockfile := range attestor.Lockfiles {
		if strings.Contains(lockfile.Filename, ".git") {
			t.Errorf("Lockfile from .git directory should have been skipped: %s", lockfile.Filename)
		}
	}

	// Verify content
	foundFiles := make(map[string]bool)
	for _, lockfile := range attestor.Lockfiles {
		expectedContent, ok := testFiles[lockfile.Filename]
		if !ok {
			t.Errorf("Unexpected lockfile found: %s", lockfile.Filename)
			continue
		}
		if lockfile.Content != expectedContent {
			t.Errorf("Content mismatch for %s", lockfile.Filename)
		}
		foundFiles[lockfile.Filename] = true
	}

	// Verify all expected files were found
	for path := range testFiles {
		if !foundFiles[path] {
			t.Errorf("Expected lockfile not found: %s", path)
		}
	}
}

func TestAttestor_Attest_RecursiveSearch_IgnoreDirectories(t *testing.T) {
	// Create temporary directory structure
	tempDir, err := os.MkdirTemp("", "lockfiles_test_ignore")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create directories including ones that should be ignored
	appDir := filepath.Join(tempDir, "app")
	nodeModulesDir := filepath.Join(tempDir, "node_modules")
	vendorDir := filepath.Join(tempDir, "vendor")

	for _, dir := range []string{appDir, nodeModulesDir, vendorDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("Failed to create dir %s: %v", dir, err)
		}
	}

	// Create lockfiles in various directories
	validLockfile := filepath.Join(appDir, "package-lock.json")
	ignoredLockfile1 := filepath.Join(nodeModulesDir, "package-lock.json")
	ignoredLockfile2 := filepath.Join(vendorDir, "Gemfile.lock")

	if err := os.WriteFile(validLockfile, []byte("valid lockfile"), 0644); err != nil {
		t.Fatalf("Failed to create valid lockfile: %v", err)
	}
	if err := os.WriteFile(ignoredLockfile1, []byte("should be ignored"), 0644); err != nil {
		t.Fatalf("Failed to create ignored lockfile 1: %v", err)
	}
	if err := os.WriteFile(ignoredLockfile2, []byte("should be ignored"), 0644); err != nil {
		t.Fatalf("Failed to create ignored lockfile 2: %v", err)
	}

	// Change to temp directory
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}
	defer func() {
		if err := os.Chdir(oldWd); err != nil {
			t.Errorf("Failed to change back to original directory: %v", err)
		}
	}()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}

	// Create attestor with recursive search
	attestor := &Attestor{
		SearchPaths: "recursive",
	}
	ctx := &attestation.AttestationContext{}

	// Run the Attest method
	err = attestor.Attest(ctx)
	if err != nil {
		t.Fatalf("Attest failed: %v", err)
	}

	// Should only find 1 lockfile (the one in app/)
	if len(attestor.Lockfiles) != 1 {
		t.Errorf("Expected 1 lockfile, but got %d", len(attestor.Lockfiles))
		for _, lf := range attestor.Lockfiles {
			t.Logf("Found: %s", lf.Filename)
		}
	}

	// Verify node_modules and vendor were skipped
	for _, lockfile := range attestor.Lockfiles {
		if strings.Contains(lockfile.Filename, "node_modules") {
			t.Errorf("Lockfile from node_modules should have been skipped: %s", lockfile.Filename)
		}
		if strings.Contains(lockfile.Filename, "vendor") {
			t.Errorf("Lockfile from vendor should have been skipped: %s", lockfile.Filename)
		}
	}

	// Verify the valid lockfile was found
	if len(attestor.Lockfiles) == 1 {
		if !strings.Contains(attestor.Lockfiles[0].Filename, "app/package-lock.json") {
			t.Errorf("Expected lockfile from app/ but got: %s", attestor.Lockfiles[0].Filename)
		}
		if attestor.Lockfiles[0].Content != "valid lockfile" {
			t.Errorf("Content mismatch for valid lockfile")
		}
	}
}
