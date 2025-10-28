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
	"crypto"
	"fmt"
	"os"
	"path/filepath"

	"github.com/invopop/jsonschema"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
)

const (
	Name    = "lockfiles"
	Type    = "https://witness.dev/attestations/lockfiles/v0.1"
	RunType = attestation.PreMaterialRunType
)

var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return NewLockfilesAttestor()
	})
}

func NewLockfilesAttestor() attestation.Attestor {
	searchPaths := os.Getenv("WITNESS_LOCKFILES_SEARCH_PATHS")
	return &Attestor{
		Lockfiles:   []LockfileInfo{},
		SearchPaths: searchPaths,
	}
}

// Attestor implements the lockfiles attestation type
type Attestor struct {
	Lockfiles   []LockfileInfo `json:"lockfiles"`
	SearchPaths string         `json:"-"` // Configuration field, not included in attestation
}

// LockfileInfo stores information about a lockfile
type LockfileInfo struct {
	Filename string               `json:"filename"`
	Content  string               `json:"content"`
	Digest   cryptoutil.DigestSet `json:"digest"`
}

// Name returns the name of the attestation type
func (a *Attestor) Name() string {
	return "lockfiles"
}

// Attest captures the contents of common lockfiles
func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	lockfilePatterns := []string{
		"Gemfile.lock",      // Ruby
		"package-lock.json", // Node.js (npm)
		"yarn.lock",         // Node.js (Yarn)
		"Cargo.lock",        // Rust
		"poetry.lock",       // Python (Poetry)
		"Pipfile.lock",      // Python (Pipenv)
		"composer.lock",     // PHP
		"go.sum",            // Go
		"Podfile.lock",      // iOS/macOS (CocoaPods)
		"gradle.lockfile",   // Gradle
		"pnpm-lock.yaml",    // Node.js (pnpm)
		"requirements.txt",  // Python (pip)
	}

	a.Lockfiles = []LockfileInfo{}

	// Determine search directories
	searchDirs := []string{"."}
	if a.SearchPaths != "" {
		if a.SearchPaths == "recursive" {
			// Recursively search from current directory
			return a.searchRecursive(".", lockfilePatterns)
		}
		// Parse comma-separated list of directories
		searchDirs = parseSearchPaths(a.SearchPaths)
	}

	// Search in specified directories
	for _, dir := range searchDirs {
		if err := a.searchInDirectory(dir, lockfilePatterns); err != nil {
			return err
		}
	}

	return nil
}

// parseSearchPaths splits a comma-separated list of paths and trims whitespace
func parseSearchPaths(paths string) []string {
	var result []string
	for _, p := range filepath.SplitList(paths) {
		trimmed := filepath.Clean(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// searchInDirectory searches for lockfiles in a specific directory
func (a *Attestor) searchInDirectory(dir string, patterns []string) error {
	for _, pattern := range patterns {
		searchPattern := filepath.Join(dir, pattern)
		matches, err := filepath.Glob(searchPattern)
		if err != nil {
			return fmt.Errorf("error searching for %s: %w", searchPattern, err)
		}

		for _, match := range matches {
			if err := a.addLockfile(match); err != nil {
				return err
			}
		}
	}
	return nil
}

// searchRecursive recursively searches for lockfiles from a root directory
func (a *Attestor) searchRecursive(root string, patterns []string) error {
	// Default directories to ignore
	defaultIgnore := map[string]bool{
		"node_modules": true,
		"vendor":       true,
		".git":         true,
		".svn":         true,
		".hg":          true,
		"__pycache__":  true,
		"venv":         true,
		".venv":        true,
		"target":       true, // Rust/Java build output
		"build":        true,
		"dist":         true,
	}

	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip ignored directories
		if info.IsDir() && path != root {
			dirName := info.Name()
			// Skip hidden directories
			if len(dirName) > 0 && dirName[0] == '.' {
				return filepath.SkipDir
			}
			// Skip default ignore directories
			if defaultIgnore[dirName] {
				return filepath.SkipDir
			}
		}

		if info.IsDir() {
			return nil
		}

		// Check if file matches any lockfile pattern
		for _, pattern := range patterns {
			if matched, _ := filepath.Match(pattern, info.Name()); matched {
				if err := a.addLockfile(path); err != nil {
					return err
				}
				break
			}
		}
		return nil
	})
}

// addLockfile reads a lockfile and adds it to the attestation
func (a *Attestor) addLockfile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("error reading %s: %w", path, err)
	}

	// Define required digest algorithms
	requiredDigestValues := []cryptoutil.DigestValue{
		{Hash: crypto.SHA256},
	}

	// Compute the digest of the lockfile content
	digest, err := cryptoutil.CalculateDigestSetFromBytes(content, requiredDigestValues)
	if err != nil {
		return fmt.Errorf("error computing digest of %s: %w", path, err)
	}

	a.Lockfiles = append(a.Lockfiles, LockfileInfo{
		Filename: path,
		Content:  string(content),
		Digest:   digest,
	})
	return nil
}

// RunType implements attestation.Attestor.
func (o *Attestor) RunType() attestation.RunType {
	return RunType
}

// // Schema implements attestation.Attestor.
func (o *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&o)
}

// Type implements attestation.Attestor.
func (o *Attestor) Type() string {
	return Type
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	subjects := make(map[string]cryptoutil.DigestSet)
	for _, lockfile := range a.Lockfiles {
		subjectName := fmt.Sprintf("file:%s", lockfile.Filename)
		subjects[subjectName] = lockfile.Digest
	}
	return subjects
}
