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
	"strings"

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
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type Attestor struct {
	OS        string            `json:"os"`
	Hostname  string            `json:"hostname"`
	Username  string            `json:"username"`
	Variables map[string]string `json:"variables,omitempty"`

	blockList     map[string]struct{}
	obfuscateList map[string]struct{}
}

type Option func(*Attestor)

func WithBlockList(blockList map[string]struct{}) Option {
	return func(a *Attestor) {
		a.blockList = blockList
	}
}

func WithObfuscateList(obfuscateList map[string]struct{}) Option {
	return func(a *Attestor) {
		for key, value := range obfuscateList {
			a.obfuscateList[key] = value
		}
	}
}

func New(opts ...Option) *Attestor {
	attestor := &Attestor{
		blockList:     DefaultBlockList(),
		obfuscateList: DefaultObfuscateList(),
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
	a.OS = runtime.GOOS
	a.Variables = make(map[string]string)

	if hostname, err := os.Hostname(); err == nil {
		a.Hostname = hostname
	}

	if user, err := user.Current(); err == nil {
		a.Username = user.Username
	}

	FilterEnvironmentArray(os.Environ(), a.blockList, func(key, val, _ string) {
		a.Variables[key] = val
	})

	ObfuscateEnvironmentArray(a.Variables, a.obfuscateList, func(key, val, _ string) {
		a.Variables[key] = val
	})

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
