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

package link

import (
	"encoding/json"
	"fmt"

	v0 "github.com/in-toto/attestation/go/predicates/link/v0"
	v1 "github.com/in-toto/attestation/go/v1"
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/commandrun"
	"github.com/in-toto/go-witness/attestation/environment"
	"github.com/in-toto/go-witness/attestation/material"
	"github.com/in-toto/go-witness/attestation/product"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/registry"
	"github.com/invopop/jsonschema"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	Name    = "link"
	Type    = "https://in-toto.io/attestation/link/v0.3"
	RunType = attestation.PostProductRunType

	defaultExport = false
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor  = &Link{}
	_ attestation.Subjecter = &Link{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType,
		func() attestation.Attestor { return New() },
		registry.BoolConfigOption(
			"export",
			"Export the Link predicate in its own attestation",
			defaultExport,
			func(a attestation.Attestor, export bool) (attestation.Attestor, error) {
				linkAttestor, ok := a.(*Link)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a Link provenance attestor", a)
				}
				WithExport(export)(linkAttestor)
				return linkAttestor, nil
			},
		),
	)
}

type Option func(*Link)

func WithExport(export bool) Option {
	return func(l *Link) {
		l.export = export
	}
}

type Link struct {
	PbLink   v0.Link
	products map[string]attestation.Product
	export   bool
}

func New() *Link {
	return &Link{}
}

func (l *Link) Name() string {
	return Name
}

func (l *Link) Type() string {
	return Type
}

func (l *Link) RunType() attestation.RunType {
	return RunType
}

func (l *Link) Schema() *jsonschema.Schema {
	// NOTE: This isn't ideal. For some reason the reflect function is return an empty schema when passing in `p`
	// TODO: Fix this later
	return jsonschema.Reflect(&v0.Link{})
}

func (l *Link) Export() bool {
	return l.export
}

func (l *Link) Attest(ctx *attestation.AttestationContext) error {
	l.PbLink.Name = ctx.StepName()
	for _, attestor := range ctx.CompletedAttestors() {
		switch name := attestor.Attestor.Name(); name {
		case commandrun.Name:
			l.PbLink.Command = attestor.Attestor.(commandrun.CommandRunAttestor).Data().Cmd
		case material.Name:
			mats := attestor.Attestor.(material.MaterialAttestor).Materials()
			for name, digestSet := range mats {
				digests, _ := digestSet.ToNameMap()
				l.PbLink.Materials = append(l.PbLink.Materials, &v1.ResourceDescriptor{
					Name:   name,
					Digest: digests,
				})
			}
		case environment.Name:
			envs := attestor.Attestor.(environment.EnvironmentAttestor).Data().Variables
			pbEnvs := make(map[string]interface{}, len(envs))
			for name, value := range envs {
				pbEnvs[name] = value
			}

			var err error
			l.PbLink.Environment, err = structpb.NewStruct(pbEnvs)
			if err != nil {
				return err
			}
		case product.ProductName:
			l.products = attestor.Attestor.(product.ProductAttestor).Products()
		}
	}
	return nil
}

func (l *Link) MarshalJSON() ([]byte, error) {
	return json.Marshal(&l.PbLink)
}

func (l *Link) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &l.PbLink); err != nil {
		return err
	}

	return nil
}

func (l *Link) Subjects() map[string]cryptoutil.DigestSet {
	subjects := make(map[string]cryptoutil.DigestSet)
	for productName, product := range l.products {
		subjects[fmt.Sprintf("file:%v", productName)] = product.Digest
	}

	return subjects
}
