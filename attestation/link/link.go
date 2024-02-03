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
	v0 "github.com/in-toto/attestation/go/predicates/link/v0"
	v1 "github.com/in-toto/attestation/go/v1"
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/commandrun"
	"github.com/in-toto/go-witness/attestation/environment"
	"github.com/in-toto/go-witness/attestation/material"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	Name    = "link"
	Type    = "https://witness.dev/attestations/link/v0.1"
	RunType = attestation.PostProductRunType
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor = &Link{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type Link struct {
	PbLink   v0.Link                        `json:"Pblink"`
	Products map[string]attestation.Product `json:"products"`
}

func New() *Link {
	return &Link{
		PbLink: v0.Link{
			Name: Name,
		},
	}
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

func (l *Link) Attest(ctx *attestation.AttestationContext) error {
	for name, digestSet := range ctx.Materials() {
		digests, _ := digestSet.ToNameMap()
		l.PbLink.Materials = append(l.PbLink.Materials, &v1.ResourceDescriptor{
			Name:   name,
			Digest: digests,
		})
	}

	l.Products = ctx.Products()

	for _, attestor := range ctx.CompletedAttestors() {
		switch name := attestor.Attestor.Name(); name {
		case commandrun.Name:
			l.PbLink.Command = attestor.Attestor.(*commandrun.CommandRun).Cmd
		case material.Name:
			mats := attestor.Attestor.(*material.Attestor).Materials()
			for name, digestSet := range mats {
				digests, _ := digestSet.ToNameMap()
				l.PbLink.Materials = append(l.PbLink.Materials, &v1.ResourceDescriptor{
					Name:   name,
					Digest: digests,
				})
			}
		case environment.Name:
			envs := attestor.Attestor.(*environment.Attestor).Variables
			pbEnvs := make(map[string]interface{}, len(envs))
			for name, value := range envs {
				pbEnvs[name] = value
			}

			var err error
			l.PbLink.Environment, err = structpb.NewStruct(pbEnvs)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
