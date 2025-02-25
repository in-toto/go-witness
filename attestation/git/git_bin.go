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

package git

import (
	"os/exec"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
)

// GitExists checks if the git binary is available.
// This can be used to fall back to go-git implementation.
func GitExists() bool {

	_, err := exec.LookPath("git")
	if err != nil {
		return false
	} else {
		return true
	}
}

// GitGetBinPath retrieves the path to the git binary that is used by the attestor.
func GitGetBinPath() (string, error) {
	path, err := exec.LookPath("git")
	if err != nil {
		return "", err
	} else {
		return path, nil
	}
}

// GitGetBinHash retrieves a sha256 hash of the git binary that is located on the system.
// The path is determined based on exec.LookPath().
func GitGetBinHash(ctx *attestation.AttestationContext) (cryptoutil.DigestSet, error) {
	path, err := exec.LookPath("git")
	if err != nil {
		return cryptoutil.DigestSet{}, err
	}

	gitBinDigest, err := cryptoutil.CalculateDigestSetFromFile(path, ctx.Hashes())
	if err != nil {
		return cryptoutil.DigestSet{}, err
	}

	if err != nil {
		return cryptoutil.DigestSet{}, err
	}

	return gitBinDigest, nil
}

// GitGetStatus retrieves the status of staging and worktree
// from the git status --porcelain output
func GitGetStatus(workDir string) (map[string]Status, error) {

	// Execute the git status --porcelain command
	cmd := exec.Command("git", "-C", workDir, "status", "--porcelain")
	outputBytes, err := cmd.Output()
	if err != nil {
		return map[string]Status{}, err
	}

	// Convert the output to a string and split into lines
	output := string(outputBytes)
	lines := strings.Split(output, "\n")

	// Iterate over the lines and parse the status
	var gitStatuses map[string]Status = make(map[string]Status)
	for _, line := range lines {
		// Skip empty lines
		if len(line) == 0 {
			continue
		}

		// The first two characters are the status codes
		repoStatus := statusCodeString(git.StatusCode(line[0]))
		worktreeStatus := statusCodeString(git.StatusCode(line[1]))
		filePath := strings.TrimSpace(line[2:])

		// Append the parsed status to the list
		gitStatuses[filePath] = Status{
			Staging:  repoStatus,
			Worktree: worktreeStatus,
		}
	}

	return gitStatuses, nil
}
