// Copyright 2021 The Witness Contributors
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

package environment

import (
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strings"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/registry"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "environment"
	Type    = "https://witness.dev/attestations/environment/v0.1"
	RunType = attestation.PreMaterialRunType
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_                                  attestation.Attestor = &Attestor{}
	_                                  EnvironmentAttestor  = &Attestor{}
	defaultFilterSensitiveVarsEnabled                       = false
	defaultDisableSensitiveVarsDefault                      = false
)

type EnvironmentAttestor interface {
	// Attestor
	Name() string
	Type() string
	RunType() attestation.RunType
	Attest(ctx *attestation.AttestationContext) error
	Data() *Attestor
}

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor { return New() },
		registry.BoolConfigOption(
			"filter-sensitive-vars",
			"Switch from obfuscate to filtering variables which removes them from the output completely.",
			defaultFilterSensitiveVarsEnabled,
			func(a attestation.Attestor, filterSensitiveVarsEnabled bool) (attestation.Attestor, error) {
				envAttestor, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a environment attestor", a)
				}

				WithFilterVarsEnabled()(envAttestor)
				return envAttestor, nil
			},
		),
		registry.BoolConfigOption(
			"disable-default-sensitive-vars",
			"Disable the default list of sensitive vars and only use the items mentioned by --attestor-environment-sensitive-key.",
			defaultDisableSensitiveVarsDefault,
			func(a attestation.Attestor, disableSensitiveVarsDefault bool) (attestation.Attestor, error) {
				envAttestor, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a environment attestor", a)
				}

				WithDisableDefaultSensitiveList()(envAttestor)
				return envAttestor, nil
			},
		),
		registry.StringSliceConfigOption(
			"sensitive-key",
			"Add keys to the list of sensitive environment keys.",
			[]string{},
			func(a attestation.Attestor, additionalKeys []string) (attestation.Attestor, error) {
				envAttestor, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a environment attestor", a)
				}

				WithAdditionalKeys(additionalKeys)(envAttestor)
				return envAttestor, nil
			},
		),
	)
}

type Attestor struct {
	OS        string            `json:"os"`
	Hostname  string            `json:"hostname"`
	Username  string            `json:"username"`
	Variables map[string]string `json:"variables,omitempty"`

	osEnviron                   func() []string
	sensitiveVarsList           map[string]struct{}
	addSensitiveVarsList        map[string]struct{}
	filterVarsEnabled           bool
	disableSensitiveVarsDefault bool
}

type Option func(*Attestor)

// WithFilterVarsEnabled will make the filter (removing) of vars the acting behavior.
// The default behavior is obfuscation of variables.
func WithFilterVarsEnabled() Option {
	return func(a *Attestor) {
		a.filterVarsEnabled = true
	}
}

// WithAdditionalKeys add additional keys to final list that is checked for sensitive variables.
func WithAdditionalKeys(additionalKeys []string) Option {
	return func(a *Attestor) {
		for _, value := range additionalKeys {
			a.addSensitiveVarsList[value] = struct{}{}
		}
	}
}

// WithDisableDefaultSensitiveList will disable the default list and only use the additional keys.
func WithDisableDefaultSensitiveList() Option {
	return func(a *Attestor) {
		a.disableSensitiveVarsDefault = true
	}
}

// WithCustomEnv will override the default os.Environ() method. This could be used to mock.
func WithCustomEnv(osEnviron func() []string) Option {
	return func(a *Attestor) {
		a.osEnviron = osEnviron
	}
}

func New(opts ...Option) *Attestor {
	attestor := &Attestor{
		sensitiveVarsList:    DefaultSensitiveEnvList(),
		addSensitiveVarsList: map[string]struct{}{},
	}

	attestor.osEnviron = os.Environ

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
	a.OS = runtime.GOOS
	a.Variables = make(map[string]string)

	if hostname, err := os.Hostname(); err == nil {
		a.Hostname = hostname
	}

	if user, err := user.Current(); err == nil {
		a.Username = user.Username
	}

	// Prepare sensitive keys list.
	var finalSensitiveKeysList map[string]struct{}
	if a.disableSensitiveVarsDefault {
		a.sensitiveVarsList = map[string]struct{}{}
	}
	finalSensitiveKeysList = a.sensitiveVarsList
	for k, v := range a.addSensitiveVarsList {
		finalSensitiveKeysList[k] = v
	}

	// Filter or obfuscate
	if a.filterVarsEnabled {
		FilterEnvironmentArray(a.osEnviron(), finalSensitiveKeysList, func(key, val, _ string) {
			a.Variables[key] = val
		})
	} else {
		ObfuscateEnvironmentArray(a.osEnviron(), finalSensitiveKeysList, func(key, val, _ string) {
			a.Variables[key] = val
		})
	}

	return nil
}

func (a *Attestor) Data() *Attestor {
	return a
}

// splitVariable splits a string representing an environment variable in the format of
// "KEY=VAL" and returns the key and val separately.
func splitVariable(v string) (key, val string) {
	parts := strings.SplitN(v, "=", 2)
	key = parts[0]
	if len(parts) > 1 {
		val = parts[1]
	}

	return
}
