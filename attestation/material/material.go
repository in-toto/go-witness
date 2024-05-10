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

package material

import (
	"encoding/json"
	"fmt"

	"github.com/gobwas/glob"
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/file"
	"github.com/in-toto/go-witness/cryptoutil"
<<<<<<< HEAD
	"github.com/invopop/jsonschema"
=======
	"github.com/in-toto/go-witness/registry"
>>>>>>> 4797229 (feat: Add material incl/excl glob)
)

const (
	Name    = "material"
	Type    = "https://witness.dev/attestations/material/v0.2"
	RunType = attestation.MaterialRunType

	defaultIncludeGlob = "*"
	defaultExcludeGlob = ""
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor   = &Attestor{}
	_ attestation.Materialer = &Attestor{}
	_ MaterialAttestor       = &Attestor{}
)

type MaterialAttestor interface {
	// Attestor
	Name() string
	Type() string
	RunType() attestation.RunType
	Attest(ctx *attestation.AttestationContext) error

	// Materialer
	Materials() map[string]cryptoutil.DigestSet
}

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor { return New() },
		registry.StringConfigOption(
			"include-glob",
			"Pattern to use when recording materials. Files that match this pattern will be included as materials in the material attestation.",
			defaultIncludeGlob,
			func(a attestation.Attestor, includeGlob string) (attestation.Attestor, error) {
				prodAttestor, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a material attestor", a)
				}

				WithIncludeGlob(includeGlob)(prodAttestor)
				return prodAttestor, nil
			},
		),
		registry.StringConfigOption(
			"exclude-glob",
			"Pattern to use when recording materials. Files that match this pattern will be excluded as materials on the material attestation.",
			defaultExcludeGlob,
			func(a attestation.Attestor, excludeGlob string) (attestation.Attestor, error) {
				prodAttestor, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a product attestor", a)
				}

				WithExcludeGlob(excludeGlob)(prodAttestor)
				return prodAttestor, nil
			},
		),
	)
}

type Option func(*Attestor)

func WithIncludeGlob(glob string) Option {
	return func(a *Attestor) {
		a.includeGlob = glob
	}
}

func WithExcludeGlob(glob string) Option {
	return func(a *Attestor) {
		a.excludeGlob = glob
	}
}

type Attestor struct {
	materials           map[string]cryptoutil.DigestSet
	includeGlob         string
	compiledIncludeGlob glob.Glob
	excludeGlob         string
	compiledExcludeGlob glob.Glob
}

type attestorJson struct {
	Materials     map[string]cryptoutil.DigestSet `json:"materials"`
	Configuration attestorConfiguration           `json:"configuration"`
}

type attestorConfiguration struct {
	IncludeGlob string `json:"includeGlob"`
	ExcludeGlob string `json:"excludeGlob"`
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

func New(opts ...Option) *Attestor {
	attestor := &Attestor{}
	for _, opt := range opts {
		opt(attestor)
	}

	return attestor
}

func (a *Attestor) Schema() *jsonschema.Schema {
	// NOTE: This isn't ideal. For some reason the reflect function is return an empty schema when passing in `a`
	// TODO: Fix this later
	return jsonschema.Reflect(struct {
		Materials map[string]cryptoutil.DigestSet
	}{})
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	compiledIncludeGlob, err := glob.Compile(a.includeGlob)
	if err != nil {
		return err
	}
	a.compiledIncludeGlob = compiledIncludeGlob

	compiledExcludeGlob, err := glob.Compile(a.excludeGlob)
	if err != nil {
		return err
	}
	a.compiledExcludeGlob = compiledExcludeGlob

	materials, err := file.RecordArtifacts(ctx.WorkingDir(), nil, ctx.Hashes(), map[string]struct{}{}, false, map[string]bool{}, compiledIncludeGlob, compiledExcludeGlob)
	if err != nil {
		return err
	}

	a.materials = materials
	return nil
}

func (a *Attestor) MarshalJSON() ([]byte, error) {
	output := attestorJson{
		Materials: a.materials,
	}

	if a.includeGlob != "" || a.excludeGlob != "" {
		config := attestorConfiguration{}

		if a.includeGlob != "" {
			config.IncludeGlob = a.includeGlob
		}
		if a.excludeGlob != "" {
			config.ExcludeGlob = a.excludeGlob
		}
	}

	return json.Marshal(output)
}

func (a *Attestor) UnmarshalJSON(data []byte) error {
	attestation := attestorJson{
		Materials: make(map[string]cryptoutil.DigestSet),
	}

	if err := json.Unmarshal(data, &attestation); err != nil {
		return err
	}

	a.materials = attestation.Materials
	a.includeGlob = attestation.Configuration.IncludeGlob
	a.excludeGlob = attestation.Configuration.ExcludeGlob
	return nil
}

func (a *Attestor) Materials() map[string]cryptoutil.DigestSet {
	return a.materials
}
