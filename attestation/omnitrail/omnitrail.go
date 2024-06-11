// Copyright 2024 The Witness Contributors
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

package omnitrail

import (
	ot "github.com/fkautz/omnitrail-go"
	"github.com/in-toto/go-witness/attestation"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "omnitrail"
	Type    = "https://witness.dev/attestations/omnitrail/v0.1"
	RunType = attestation.PreMaterialRunType
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return NewOmnitrailAttestor()
	})
}

type Attestor struct {
	Envelope *ot.Envelope `json:"Envelope"`
}

func NewOmnitrailAttestor() *Attestor {
	return &Attestor{}
}

// Attest implements attestation.Attestor.
func (o *Attestor) Attest(ctx *attestation.AttestationContext) error {
	trail := ot.NewTrail()
	err := trail.Add(ctx.WorkingDir())
	if err != nil {
		return err
	}
	o.Envelope = trail.Envelope()
	return nil
}

// Name implements attestation.Attestor.
func (o *Attestor) Name() string {
	return Name
}

// RunType implements attestation.Attestor.
func (o *Attestor) RunType() attestation.RunType {
	return RunType
}

// // Schema implements attestation.Attestor.
func (o *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&o)
}

// Type implements attestation.Attestor.
func (o *Attestor) Type() string {
	return Type
}
