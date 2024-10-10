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
	"os"
	"os/user"
	"runtime"

	"github.com/in-toto/go-witness/attestation"
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
	// attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor { return New() },
	// 	registry.BoolConfigOption(
	// 		"filter-sensitive-vars",
	// 		"Switch from obfuscate to filtering variables which removes them from the output completely.",
	// 		defaultFilterSensitiveVarsEnabled,
	// 		func(a attestation.Attestor, filterSensitiveVarsEnabled bool) (attestation.Attestor, error) {
	// 			envAttestor, ok := a.(*Attestor)
	// 			if !ok {
	// 				return a, fmt.Errorf("unexpected attestor type: %T is not a environment attestor", a)
	// 			}

	// 			envCapture.WithFilterVarsEnabled()(envAttestor.capture)
	// 			return envAttestor, nil
	// 		},
	// 	),
	// 	registry.BoolConfigOption(
	// 		"disable-default-sensitive-vars",
	// 		"Disable the default list of sensitive vars and only use the items mentioned by --attestor-environment-sensitive-key.",
	// 		defaultDisableSensitiveVarsDefault,
	// 		func(a attestation.Attestor, disableSensitiveVarsDefault bool) (attestation.Attestor, error) {
	// 			envAttestor, ok := a.(*Attestor)
	// 			if !ok {
	// 				return a, fmt.Errorf("unexpected attestor type: %T is not a environment attestor", a)
	// 			}

	// 			envCapture.WithDisableDefaultSensitiveList()(envAttestor.capture)
	// 			return envAttestor, nil
	// 		},
	// 	),
	// 	registry.StringSliceConfigOption(
	// 		"add-sensitive-key",
	// 		"Add keys or globs (e.g. '*TEXT') to the list of sensitive environment keys.",
	// 		[]string{},
	// 		func(a attestation.Attestor, additionalKeys []string) (attestation.Attestor, error) {
	// 			envAttestor, ok := a.(*Attestor)
	// 			if !ok {
	// 				return a, fmt.Errorf("unexpected attestor type: %T is not a environment attestor", a)
	// 			}

	// 			envCapture.WithAdditionalKeys(additionalKeys)(envAttestor.capture)
	// 			return envAttestor, nil
	// 		},
	// 	),
	// 	registry.StringSliceConfigOption(
	// 		"exclude-sensitive-key",
	// 		"Exclude specific keys from the list of sensitive environment keys. Note: This does not support globs.",
	// 		[]string{},
	// 		func(a attestation.Attestor, excludeKeys []string) (attestation.Attestor, error) {
	// 			envAttestor, ok := a.(*Attestor)
	// 			if !ok {
	// 				return a, fmt.Errorf("unexpected attestor type: %T is not a environment attestor", a)
	// 			}

	// 			envCapture.WithExcludeKeys(excludeKeys)(envAttestor.capture)
	// 			return envAttestor, nil
	// 		},
	// 	),
	// )
}

type Attestor struct {
	OS        string            `json:"os"`
	Hostname  string            `json:"hostname"`
	Username  string            `json:"username"`
	Variables map[string]string `json:"variables,omitempty"`

	osEnviron func() []string
}

type Option func(*Attestor)

// WithCustomEnv will override the default os.Environ() method. This could be used to mock.
func WithCustomEnv(osEnviron func() []string) Option {
	return func(a *Attestor) {
		a.osEnviron = osEnviron
	}
}

func New(opts ...Option) *Attestor {
	attestor := &Attestor{}

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

	a.Variables = ctx.EnvironmentCapturer().Capture(a.osEnviron())

	return nil
}

func (a *Attestor) Data() *Attestor {
	return a
}
