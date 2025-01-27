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

package systempackages

import (
	"bufio"
	"os/exec"
	"strings"
)

type DebianBackend struct {
	osReleaseFile string
	execCommand   func(name string, arg ...string) *exec.Cmd
}

func NewDebianBackend(osReleaseFile string) Backend {
	return &DebianBackend{
		osReleaseFile: osReleaseFile,
		execCommand:   exec.Command,
	}
}

func (b *DebianBackend) SetExecCommand(cmd func(name string, arg ...string) *exec.Cmd) {
	b.execCommand = cmd
}

func (b *DebianBackend) DetermineOSInfo() (string, string, string, error) {
	return determineDistribution(b.osReleaseFile)
}

func (b *DebianBackend) GatherPackages() ([]Package, error) {
	cmd := b.execCommand("dpkg-query", "-W", "-f", "${Package}\t${Version}\n")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var packages []Package
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "\t")
		if len(parts) == 2 {
			packages = append(packages, Package{
				Name:    parts[0],
				Version: parts[1],
			})
		}
	}

	return packages, nil
}
