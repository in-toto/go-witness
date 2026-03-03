// Copyright 2025 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package configuration

import (
	"os"
	"strings"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/invopop/jsonschema"
	"gopkg.in/yaml.v3"
)

const (
	Name    = "configuration"
	Type    = "https://witness.dev/attestations/configuration/v0.1"
	RunType = attestation.PreMaterialRunType
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor  = &Attestor{}
	_ ConfigurationAttestor = &Attestor{}
)

type ConfigurationAttestor interface {
	// Attestor
	Name() string
	Type() string
	RunType() attestation.RunType
	Attest(ctx *attestation.AttestationContext) error
	Data() *Attestor
}

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor { return New() })
}

type Attestor struct {
	Flags         map[string]string      `json:"flags,omitempty"`
	ConfigPath    string                 `json:"config_path,omitempty"`
	ConfigDigest  cryptoutil.DigestSet   `json:"config_digest,omitempty"`
	ConfigContent map[string]interface{} `json:"config_content,omitempty"`
	WorkingDir    string                 `json:"working_directory,omitempty"`

	osArgs func() []string
}

type Option func(*Attestor)

func WithCustomArgs(osArgs func() []string) Option {
	return func(a *Attestor) {
		a.osArgs = osArgs
	}
}

func New(opts ...Option) *Attestor {
	attestor := &Attestor{}

	attestor.osArgs = func() []string {
		return os.Args
	}

	for _, opt := range opts {
		opt(attestor)
	}

	return attestor
}

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) Type() string {
	return Type
}

func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&a)
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	args := a.osArgs()
	witnessArgs := extractWitnessArgs(args)
	a.Flags = parseFlags(witnessArgs)

	// Capture working directory
	if wd, err := os.Getwd(); err == nil {
		a.WorkingDir = wd
	}

	// Config path: flag or default
	if v, ok := a.Flags["config"]; ok && v != "" {
		a.ConfigPath = v
	} else if v, ok := a.Flags["c"]; ok && v != "" {
		a.ConfigPath = v
	} else {
		a.ConfigPath = ".witness.yaml"
	}

	// Config digest and content if file exists
	if data, err := os.ReadFile(a.ConfigPath); err == nil {
		digestSet, err := cryptoutil.CalculateDigestSetFromBytes(data, ctx.Hashes())
		if err == nil {
			a.ConfigDigest = digestSet
		}

		// Parse and store config content
		var configData map[string]interface{}
		if err := yaml.Unmarshal(data, &configData); err == nil {
			a.ConfigContent = configData
		}
	}

	return nil
}

// extractWitnessArgs splits the command line at "--" and returns only the witness portion
// Example: ["witness", "run", "-a", "slsa", "--", "go", "build", "."] -> ["witness", "run", "-a", "slsa"]
func extractWitnessArgs(args []string) []string {
	for i, arg := range args {
		if arg == "--" {
			return args[:i]
		}
	}
	return args
}

// parseFlags parses command line flags into a map
func parseFlags(cmd []string) map[string]string {
	flags := make(map[string]string)

	for i := 1; i < len(cmd); i++ {
		arg := cmd[i]

		if strings.HasPrefix(arg, "--") {
			key := strings.TrimPrefix(arg, "--")

			if strings.Contains(key, "=") {
				parts := strings.SplitN(key, "=", 2)
				flags[parts[0]] = parts[1]
				continue
			}

			if i+1 < len(cmd) && !strings.HasPrefix(cmd[i+1], "-") {
				flags[key] = cmd[i+1]
				i++
			} else {
				flags[key] = "true"
			}
		} else if strings.HasPrefix(arg, "-") && len(arg) > 1 && !strings.HasPrefix(arg, "--") {
			key := strings.TrimPrefix(arg, "-")

			if strings.Contains(key, "=") {
				parts := strings.SplitN(key, "=", 2)
				flags[parts[0]] = parts[1]
				continue
			}

			if i+1 < len(cmd) && !strings.HasPrefix(cmd[i+1], "-") {
				flags[key] = cmd[i+1]
				i++
			} else {
				flags[key] = "true"
			}
		}
	}

	return flags
}

func (a *Attestor) Data() *Attestor {
	return a
}
