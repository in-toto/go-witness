// Copyright 2022 The Witness Contributors
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

package docker

import (
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	docker "github.com/in-toto/go-witness/internal/docker"
	"github.com/in-toto/go-witness/log"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "docker"
	Type    = "https://witness.dev/attestations/docker/v0.1"
	RunType = attestation.PostProductRunType

	sha256MimeType = "text/sha256+text"
	jsonMimeType   = "application/json"
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type Attestor struct {
	Products map[string]DockerProduct `json:"products" jsonschema:"title=Docker Products,description=Map of Docker image digests to product information"`
}

type DockerProduct struct {
	Materials       map[string][]Material `json:"materials" jsonschema:"title=Build Materials,description=Materials used to build the image by architecture"`
	ImageReferences []string              `json:"imagereferences" jsonschema:"title=Image References,description=Docker image names and tags"`
	ImageDigest     cryptoutil.DigestSet  `json:"imagedigest" jsonschema:"title=Image Digest,description=Content-addressable digest of the Docker image"`
}

type Material struct {
	URI          string               `json:"uri" jsonschema:"title=Material URI,description=URI of the build material"`
	Architecture string               `json:"architecture" jsonschema:"title=Architecture,description=Target architecture for this material"`
	Digest       cryptoutil.DigestSet `json:"digest" jsonschema:"title=Material Digest,description=Cryptographic digest of the material"`
}

type Manifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

func New() *Attestor {
	return &Attestor{}
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
	mets, err := a.getDockerCandidates(ctx)
	if err != nil {
		log.Debugf("(attestation/docker) error getting docker candidate: %w", err)
		return err
	}

	if mets != nil {
		a.Products = map[string]DockerProduct{}
		for _, met := range mets {
			log.Debugf("(attestation/docker) setting docker candidate for image '%s'", met.ImageName)
			err := a.setDockerCandidate(&met)
			if err != nil {
				log.Debugf("(attestation/docker) error setting docker candidate: %w", err)
				return err
			}
		}
	}

	if len(a.Products) == 0 {
		return fmt.Errorf("no products to attest")
	}

	return nil
}

func (a *Attestor) setDockerCandidate(met *docker.BuildInfo) error {
	if !strings.HasPrefix(met.ContainerImageDigest, "sha256:") {
		// NOTE: If we find that there is not a digest, we can't deterministically say what the image is and therefore we will not attest it
		log.Warnf("(attestation/docker) found metadata file does not contain image digest of expected sha256 format: '%s'", met.ContainerImageDigest)
		return nil
	}

	log.Debugf("(attestation/docker) found image digest '%s'", met.ContainerImageDigest)
	trimmed, found := strings.CutPrefix(met.ContainerImageDigest, "sha256:")
	log.Debugf("(attestation/docker) removing 'sha256:' prefix from digest '%s'", met.ContainerImageDigest)
	if !found {
		err := fmt.Errorf("failed to remove prefix from digest")
		log.Debugf("(attestation/docker) %s", err.Error())
		return err
	}

	log.Debugf("(attestation/docker) setting image digest as '%s'", trimmed)

	materials := make(map[string][]Material)
	for arch, prov := range met.Provenance {
		if len(prov.Materials) != 0 {
			for _, material := range prov.Materials {
				mat := Material{
					Architecture: arch,
					URI:          material.URI,
					Digest: cryptoutil.DigestSet{
						cryptoutil.DigestValue{
							Hash:    crypto.SHA256,
							GitOID:  false,
							DirHash: false,
						}: material.Digest.Sha256,
					},
				}

				if materials[arch] == nil {
					materials[arch] = []Material{
						mat,
					}
				} else {
					materials[arch] = append(materials[arch], mat)
				}
			}
		}
	}

	log.Debugf("setting image references as '%s'", met.ImageName)
	imageReferences := []string{}
	imageReferences = append(imageReferences, met.ImageName)

	a.Products[trimmed] = DockerProduct{
		ImageDigest: map[cryptoutil.DigestValue]string{
			{Hash: crypto.SHA256}: trimmed,
		},
		Materials:       materials,
		ImageReferences: imageReferences,
	}
	return nil
}

func (a *Attestor) getDockerCandidates(ctx *attestation.AttestationContext) ([]docker.BuildInfo, error) {
	products := ctx.Products()

	if len(products) == 0 {
		return nil, fmt.Errorf("no products to attest")
	}

	// NOTE: it's not ideal to try and parse it without a dedicated mime type (using json here)
	// but the metadata file is completely different depending on how the buildx is executed
	mets := []docker.BuildInfo{}
	for path, product := range products {
		if strings.Contains(jsonMimeType, product.MimeType) {
			var met docker.BuildInfo
			f, err := os.ReadFile(filepath.Join(ctx.WorkingDir(), path))
			if err != nil {
				return nil, fmt.Errorf("failed to read file %s: %w", path, err)
			}

			err = json.Unmarshal(f, &met)
			if err != nil {
				log.Debugf("(attestation/docker) error parsing file %s as docker metadata file: %w", path, err)
				continue
			}

			mets = append(mets, met)
		}
	}

	return mets, nil
}

func (a *Attestor) Documentation() attestation.Documentation {
	return attestation.Documentation{
		Summary: "Captures Docker image build metadata including digests, materials, and provenance",
		Usage: []string{
			"Record Docker buildx metadata for supply chain verification",
			"Track multi-architecture build materials and dependencies",
			"Link Docker images to their build inputs",
		},
		Example: "witness run -s package -k key.pem -a docker -- docker build -t myapp:latest .",
	}
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	subj := make(map[string]cryptoutil.DigestSet)
	for _, p := range a.Products {
		subj[fmt.Sprintf("imagedigest:%s", p.ImageDigest[cryptoutil.DigestValue{Hash: crypto.SHA256}])] = p.ImageDigest

		for _, ir := range p.ImageReferences {
			if hash, err := cryptoutil.CalculateDigestSetFromBytes([]byte(ir), hashes); err == nil {
				subj[fmt.Sprintf("imagereference:%s", ir)] = hash
			} else {
				log.Debugf("(attestation/docker) failed to record github imagereference subject: %w", err)
			}
		}

		// NOTE: Not sure if we should use the architecture here...
		for _, mat := range p.Materials {
			for _, m := range mat {
				subj[fmt.Sprintf("materialdigest:%s", m.Digest[cryptoutil.DigestValue{Hash: crypto.SHA256}])] = m.Digest
				if hash, err := cryptoutil.CalculateDigestSetFromBytes([]byte(m.URI), hashes); err == nil {
					subj[fmt.Sprintf("materialuri:%s", m.URI)] = hash
				} else {
					log.Debugf("(attestation/github) failed to record github materialuri subject: %w", err)
				}
			}
		}

		for _, ref := range p.ImageReferences {
			hash, err := cryptoutil.CalculateDigestSetFromBytes([]byte(ref), hashes)
			if err != nil {
				log.Debugf("(attestation/docker) error calculating image reference: %w", err)
				continue
			}
			subj[fmt.Sprintf("imagereference:%s", ref)] = hash
		}
	}

	return subj
}
