// Copyright 2023 The Witness Contributors
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
