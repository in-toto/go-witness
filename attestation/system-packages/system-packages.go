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
	"crypto"
	"encoding/json"
	"os"
	"os/exec"
	"strings"

	"github.com/in-toto/go-witness/cryptoutil"

	"github.com/in-toto/go-witness/attestation"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "system-packages"
	Type    = "https://witness.dev/attestations/system-packages/v0.1"
	RunType = attestation.PreMaterialRunType
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return NewSystemPackagesAttestor()
	})
}

type Attestor struct {
	OS           string               `json:"os"`
	Distribution string               `json:"distribution"`
	Version      string               `json:"version"`
	Packages     []Package            `json:"packages"`
	Digest       cryptoutil.DigestSet `json:"digest"`
	backend      Backend
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Backend interface {
	DetermineOSInfo() (string, string, string, error)
	GatherPackages() ([]Package, error)
	SetExecCommand(cmd func(name string, arg ...string) *exec.Cmd)
}

func NewSystemPackagesAttestor() *Attestor {
	osReleaseFile := "/etc/os-release"
	_, distribution, _, err := determineDistribution(osReleaseFile)
	if err != nil {
		// Default to Debian-based system if we can't determine the distribution
		return &Attestor{
			backend: NewDebianBackend(osReleaseFile),
		}
	}

	switch distribution {
	case "fedora", "rhel", "centos", "rocky", "alma", "oracle", "suse", "opensuse", "amazon":
		return &Attestor{
			backend: NewRPMBackend(osReleaseFile),
		}
	case "debian", "ubuntu":
		return &Attestor{
			backend: NewDebianBackend(osReleaseFile),
		}
	default:
		// Use Debian backend for any other unrecognized distributions
		return &Attestor{
			backend: NewDebianBackend(osReleaseFile),
		}
	}
}

func determineDistribution(osReleaseFile string) (string, string, string, error) {
	file, err := os.Open(osReleaseFile)
	if err != nil {
		return "", "", "", err
	}
	defer file.Close()

	var distribution, version string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), "\"")

		switch key {
		case "ID":
			distribution = value
		case "VERSION_ID":
			version = value
		}
	}

	if err := scanner.Err(); err != nil {
		return "", "", "", err
	}

	return "linux", distribution, version, nil
}

// Attest implements attestation.Attestor.
func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	os, dist, version, err := a.backend.DetermineOSInfo()
	if err != nil {
		return err
	}
	a.OS = os
	a.Distribution = dist
	a.Version = version

	packages, err := a.backend.GatherPackages()
	if err != nil {
		return err
	}
	a.Packages = packages

	// Define required digest algorithms
	requiredDigestValues := []cryptoutil.DigestValue{
		{Hash: crypto.SHA256},
	}

	digestableAttestor := &Attestor{
		OS:           a.OS,
		Distribution: a.Distribution,
		Version:      a.Version,
		Packages:     a.Packages,
	}

	content, err := json.Marshal(digestableAttestor)
	if err != nil {
		return err
	}

	digest, err := cryptoutil.CalculateDigestSetFromBytes(content, requiredDigestValues)
	if err != nil {
		return err
	}

	a.Digest = digest

	return nil
}

// Name implements attestation.Attestor.
func (a *Attestor) Name() string {
	return Name
}

// RunType implements attestation.Attestor.
func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

// Schema implements attestation.Attestor.
func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(a)
}

// Type implements attestation.Attestor.
func (a *Attestor) Type() string {
	return Type
}
