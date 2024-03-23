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

package slsa

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	prov "github.com/in-toto/attestation/go/predicates/provenance/v1"
	v1 "github.com/in-toto/attestation/go/v1"
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/commandrun"
	"github.com/in-toto/go-witness/attestation/environment"
	"github.com/in-toto/go-witness/attestation/git"
	"github.com/in-toto/go-witness/attestation/material"
	"github.com/in-toto/go-witness/attestation/product"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/registry"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	Name    = "slsa"
	Type    = "https://slsa.dev/provenance/v1.0"
	RunType = attestation.PostProductRunType

	defaultExport = false
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor  = &Provenance{}
	_ attestation.Subjecter = &Provenance{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType,
		func() attestation.Attestor { return New() },
		registry.BoolConfigOption(
			"export",
			"Export the SLSA provenance attestation to its own file",
			defaultExport,
			func(a attestation.Attestor, export bool) (attestation.Attestor, error) {
				slsaAttestor, ok := a.(*Provenance)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a SLSA provenance attestor", a)
				}
				WithExport(export)(slsaAttestor)
				return slsaAttestor, nil
			},
		),
	)
}

type Option func(*Provenance)

func WithExport(export bool) Option {
	return func(l *Provenance) {
		l.export = export
	}
}

type Provenance struct {
	PbProvenance prov.Provenance
	products     map[string]attestation.Product
	export       bool
}

func New() *Provenance {
	return &Provenance{}
}

func (l *Provenance) Name() string {
	return Name
}

func (l *Provenance) Type() string {
	return Type
}

func (l *Provenance) RunType() attestation.RunType {
	return RunType
}

func (l *Provenance) Export() bool {
	return l.export
}

func (l *Provenance) Attest(ctx *attestation.AttestationContext) error {
	builder := prov.Builder{}
	metadata := prov.BuildMetadata{}
	l.PbProvenance.BuildDefinition = &prov.BuildDefinition{}
	l.PbProvenance.RunDetails = &prov.RunDetails{Builder: &builder, Metadata: &metadata}

	l.PbProvenance.BuildDefinition.BuildType = "https://witness.dev/slsa-build@v0.1"
	l.PbProvenance.RunDetails.Builder.Id = "https://witness.dev/witness-github-action@v0.1"
	l.PbProvenance.RunDetails.Metadata.InvocationId = "gha-workflow-ref"

	internalParamaters := make(map[string]interface{})

	for _, attestor := range ctx.CompletedAttestors() {
		switch name := attestor.Attestor.Name(); name {
		case git.Name:
			digestSet := attestor.Attestor.(*git.Attestor).CommitDigest
			remotes := attestor.Attestor.(*git.Attestor).Remotes
			digests, _ := digestSet.ToNameMap()

			for _, remote := range remotes {
				l.PbProvenance.BuildDefinition.ResolvedDependencies = append(
					l.PbProvenance.BuildDefinition.ResolvedDependencies,
					&v1.ResourceDescriptor{
						Name:   remote,
						Digest: digests,
					})
			}

		case commandrun.Name:
			var err error
			ep := make(map[string]interface{})
			ep["command"] = strings.Join(attestor.Attestor.(*commandrun.CommandRun).Cmd, " ")
			l.PbProvenance.BuildDefinition.ExternalParameters, err = structpb.NewStruct(ep)
			if err != nil {
				return err
			}
			// We have start and finish time at the collection level, how do we access it here?
			l.PbProvenance.RunDetails.Metadata.StartedOn = timestamppb.New(time.Now())
			l.PbProvenance.RunDetails.Metadata.FinishedOn = timestamppb.New(time.Now())

		case material.Name:
			mats := attestor.Attestor.(*material.Attestor).Materials()
			for name, digestSet := range mats {
				digests, _ := digestSet.ToNameMap()
				l.PbProvenance.BuildDefinition.ResolvedDependencies = append(
					l.PbProvenance.BuildDefinition.ResolvedDependencies,
					&v1.ResourceDescriptor{
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

			internalParamaters["env"] = pbEnvs

		case product.Name:
			l.products = attestor.Attestor.(*product.Attestor).Products()
		}
	}

	var err error
	l.PbProvenance.BuildDefinition.InternalParameters, err = structpb.NewStruct(internalParamaters)
	if err != nil {
		return err
	}

	return nil
}

func (l *Provenance) MarshalJSON() ([]byte, error) {
	return json.Marshal(&l.PbProvenance)
}

func (l *Provenance) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &l.PbProvenance); err != nil {
		return err
	}

	return nil
}

func (l *Provenance) Subjects() map[string]cryptoutil.DigestSet {
	subjects := make(map[string]cryptoutil.DigestSet)
	for productName, product := range l.products {
		subjects[fmt.Sprintf("file:%v", productName)] = product.Digest
	}

	return subjects
}
