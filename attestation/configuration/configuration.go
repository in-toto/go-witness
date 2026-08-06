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
	"fmt"
	"os"

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

// ResolvedValue is a single configuration value as resolved by the frontend,
// with its source: "commandline", "config", "env", or "default".
type ResolvedValue struct {
	Value  any    `json:"value"`
	Source string `json:"source,omitempty"`
}

type Attestor struct {
	CommandLine   []string                  `json:"command_line,omitempty"`
	Resolved      map[string]ResolvedValue  `json:"resolved,omitempty"`
	ConfigPath    string                    `json:"config_path,omitempty"`
	ConfigDigest  cryptoutil.DigestSet      `json:"config_digest,omitempty"`
	ConfigContent map[string]any            `json:"config_content,omitempty"`
	Attestors     map[string]map[string]any `json:"attestors,omitempty"`
	WorkingDir    string                    `json:"working_directory,omitempty"`
}

type Option func(*Attestor)

// WithCommandLine records the frontend's raw argv verbatim. The attestor never
// reads os.Args itself so library consumers don't leak their host process args.
func WithCommandLine(args []string) Option {
	return func(a *Attestor) {
		a.CommandLine = args
	}
}

// WithResolvedConfig records the fully-merged config as resolved by the
// frontend (e.g. pflag/viper for the witness CLI).
func WithResolvedConfig(resolved map[string]ResolvedValue) Option {
	return func(a *Attestor) {
		a.Resolved = resolved
	}
}

func WithConfigFile(path string) Option {
	return func(a *Attestor) {
		a.ConfigPath = path
	}
}

func New(opts ...Option) *Attestor {
	attestor := &Attestor{}
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
	if wd := ctx.WorkingDir(); wd != "" {
		a.WorkingDir = wd
	} else if wd, err := os.Getwd(); err == nil {
		a.WorkingDir = wd
	}

	if a.ConfigPath != "" {
		data, err := os.ReadFile(a.ConfigPath)
		if err != nil {
			return fmt.Errorf("failed to read config file %v: %w", a.ConfigPath, err)
		}

		digestSet, err := cryptoutil.CalculateDigestSetFromBytes(data, ctx.Hashes())
		if err != nil {
			return fmt.Errorf("failed to digest config file %v: %w", a.ConfigPath, err)
		}
		a.ConfigDigest = digestSet

		var configData map[string]any
		if err := yaml.Unmarshal(data, &configData); err != nil {
			return fmt.Errorf("failed to parse config file %v: %w", a.ConfigPath, err)
		}
		a.ConfigContent = configData
	}

	for _, att := range ctx.Attestors() {
		if att.Name() == Name {
			continue
		}

		if configurer, ok := att.(attestation.Configurer); ok {
			if a.Attestors == nil {
				a.Attestors = make(map[string]map[string]any)
			}
			a.Attestors[att.Name()] = configurer.Configuration()
		}
	}

	return nil
}

func (a *Attestor) Data() *Attestor {
	return a
}
