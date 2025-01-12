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
	_ attestation.Attestor = &Attestor{}
	_ EnvironmentAttestor  = &Attestor{}
	// defaultFilterSensitiveVarsEnabled                       = false
	// defaultDisableSensitiveVarsDefault                      = false
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
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor { return New() })
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
