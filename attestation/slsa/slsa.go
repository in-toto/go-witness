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

	prov "github.com/in-toto/attestation/go/predicates/provenance/v1"
	v1 "github.com/in-toto/attestation/go/v1"
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/commandrun"
	"github.com/in-toto/go-witness/attestation/environment"
	"github.com/in-toto/go-witness/attestation/git"
	"github.com/in-toto/go-witness/attestation/github"
	"github.com/in-toto/go-witness/attestation/gitlab"
	"github.com/in-toto/go-witness/attestation/jenkins"
	"github.com/in-toto/go-witness/attestation/material"
	"github.com/in-toto/go-witness/attestation/oci"
	"github.com/in-toto/go-witness/attestation/product"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/registry"
	"github.com/invopop/jsonschema"
	"golang.org/x/exp/maps"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	Name             = "slsa"
	Type             = "https://slsa.dev/provenance/v1.0"
	RunType          = attestation.PostProductRunType
	defaultExport    = false
	BuildType        = "https://witness.dev/slsa-build@v0.1"
	DefaultBuilderId = "https://witness.dev/witness-default-builder@v0.1"
	GHABuilderId     = "https://witness.dev/witness-github-action-builder@v0.1"
	GLCBuilderId     = "https://witness.dev/witness-gitlab-component-builder@v0.1"
	JenkinsBuilderId = "https://witness.dev/witness-jenkins-component-builder@v0.1"
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
			"Export the SLSA provenance predicate in its own attestation",
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
	return func(p *Provenance) {
		p.export = export
	}
}

type Provenance struct {
	PbProvenance prov.Provenance
	products     map[string]attestation.Product
	subjects     map[string]cryptoutil.DigestSet
	export       bool
}

func New() *Provenance {
	return &Provenance{}
}

func (p *Provenance) Name() string {
	return Name
}

func (p *Provenance) Type() string {
	return Type
}

func (p *Provenance) RunType() attestation.RunType {
	return RunType
}

func (p *Provenance) Schema() *jsonschema.Schema {
	// NOTE: This isn't ideal. For some reason the reflect function is return an empty schema when passing in `p`
	// TODO: Fix this later
	return jsonschema.Reflect(prov.Provenance{})
}

func (p *Provenance) Export() bool {
	return p.export
}

func (p *Provenance) Attest(ctx *attestation.AttestationContext) error {
	builder := prov.Builder{}
	metadata := prov.BuildMetadata{}
	p.PbProvenance.BuildDefinition = &prov.BuildDefinition{}
	p.PbProvenance.RunDetails = &prov.RunDetails{Builder: &builder, Metadata: &metadata}

	p.PbProvenance.BuildDefinition.BuildType = BuildType
	p.PbProvenance.RunDetails.Builder.Id = DefaultBuilderId

	internalParameters := make(map[string]interface{})

	for _, attestor := range ctx.CompletedAttestors() {
		switch name := attestor.Attestor.Name(); name {
		// Pre-material Attestors
		case environment.Name:
			envs := attestor.Attestor.(environment.EnvironmentAttestor).Data().Variables
			pbEnvs := make(map[string]interface{}, len(envs))
			for name, value := range envs {
				pbEnvs[name] = value
			}

			internalParameters["env"] = pbEnvs

		case git.Name:
			digestSet := attestor.Attestor.(git.GitAttestor).Data().CommitDigest
			remotes := attestor.Attestor.(git.GitAttestor).Data().Remotes
			digests, _ := digestSet.ToNameMap()

			for _, remote := range remotes {
				p.PbProvenance.BuildDefinition.ResolvedDependencies = append(
					p.PbProvenance.BuildDefinition.ResolvedDependencies,
					&v1.ResourceDescriptor{
						Name:   remote,
						Digest: digests,
					})
			}

		case github.Name:
			gh := attestor.Attestor.(github.GitHubAttestor)
			p.PbProvenance.RunDetails.Builder.Id = GHABuilderId
			p.PbProvenance.RunDetails.Metadata.InvocationId = gh.Data().PipelineUrl
			digest := make(map[string]string)

			if gh.Data().JWT == nil {
				log.Warn("No JWT found in GitHub attestor")
				continue
			}

			digest["sha1"] = gh.Data().JWT.Claims["sha"].(string)

		case gitlab.Name:
			gl := attestor.Attestor.(gitlab.GitLabAttestor)
			p.PbProvenance.RunDetails.Builder.Id = GLCBuilderId
			p.PbProvenance.RunDetails.Metadata.InvocationId = gl.Data().PipelineUrl
			digest := make(map[string]string)

			if gl.Data().JWT == nil {
				log.Warn("No JWT found in GitLab attestor")
				continue
			}

			sha, found := gl.Data().JWT.Claims["sha"]
			if found {
				digest["sha1"] = sha.(string)
			} else {
				log.Warn("No SHA found in GitLab JWT")
			}

		case jenkins.Name:
			jks := attestor.Attestor.(jenkins.JenkinsAttestor)
			p.PbProvenance.RunDetails.Builder.Id = JenkinsBuilderId
			p.PbProvenance.RunDetails.Metadata.InvocationId = jks.Data().PipelineUrl

		// Material Attestors
		case material.Name:
			mats := attestor.Attestor.(material.MaterialAttestor).Materials()
			for name, digestSet := range mats {
				digests, _ := digestSet.ToNameMap()
				p.PbProvenance.BuildDefinition.ResolvedDependencies = append(
					p.PbProvenance.BuildDefinition.ResolvedDependencies,
					&v1.ResourceDescriptor{
						Name:   name,
						Digest: digests,
					})
			}

		// CommandRun Attestors
		case commandrun.Name:
			var err error
			ep := make(map[string]interface{})
			ep["command"] = strings.Join(attestor.Attestor.(commandrun.CommandRunAttestor).Data().Cmd, " ")
			p.PbProvenance.BuildDefinition.ExternalParameters, err = structpb.NewStruct(ep)
			if err != nil {
				return err
			}

			p.PbProvenance.RunDetails.Metadata.StartedOn = timestamppb.New(attestor.StartTime)
			p.PbProvenance.RunDetails.Metadata.FinishedOn = timestamppb.New(attestor.EndTime)

		// Product Attestors
		case product.ProductName:
			if p.products == nil {
				p.products = ctx.Products()
			} else {
				maps.Copy(p.products, ctx.Products())
			}

			if p.subjects == nil {
				p.subjects = attestor.Attestor.(attestation.Subjecter).Subjects()
			} else {
				maps.Copy(p.subjects, attestor.Attestor.(attestation.Subjecter).Subjects())
			}

		// Post Attestors
		case oci.Name:
			if p.subjects == nil {
				p.subjects = attestor.Attestor.(attestation.Subjecter).Subjects()
			} else {
				maps.Copy(p.subjects, attestor.Attestor.(attestation.Subjecter).Subjects())
			}
		}
	}

	// NOTE: We want to warn users that they can use the github and gitlab attestors to enrich their provenance
	if p.PbProvenance.RunDetails.Builder.Id == DefaultBuilderId {
		log.Warn("No build system attestor invoked. Consider using github, gitlab, or jenkins attestors (if appropriate) to enrich your SLSA provenance")
	}

	var err error
	p.PbProvenance.BuildDefinition.InternalParameters, err = structpb.NewStruct(internalParameters)
	if err != nil {
		return err
	}

	return nil
}

func (p *Provenance) MarshalJSON() ([]byte, error) {
	return json.Marshal(&p.PbProvenance)
}

func (p *Provenance) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &p.PbProvenance); err != nil {
		return err
	}

	return nil
}

func (p *Provenance) Subjects() map[string]cryptoutil.DigestSet {
	subjects := make(map[string]cryptoutil.DigestSet)
	for productName, product := range p.products {
		subjects[fmt.Sprintf("file:%v", productName)] = product.Digest
	}

	return subjects
}
