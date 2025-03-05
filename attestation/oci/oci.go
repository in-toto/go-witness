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

package oci

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
	Name    = "oci"
	Type    = "https://witness.dev/attestations/oci/v0.1"
	RunType = attestation.PostProductRunType

	sha256MimeType = "text/sha256+text"
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
	_ OCIAttestor           = &Attestor{}
)

type OCIAttestor interface {
	// Attestor
	Name() string
	Type() string
	RunType() attestation.RunType
	Attest(ctx *attestation.AttestationContext) error

	// Subjector
	Subjects() map[string]cryptoutil.DigestSet
}

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type Attestor struct {
	Materials       []Material           `json:"materials"`
	ImageReferences []string             `json:"imagereferences"`
	ImageDigest     cryptoutil.DigestSet `json:"imagedigest"`
}

type Material struct {
	URI    string               `json:"uri"`
	Digest cryptoutil.DigestSet `json:"digest"`
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
	met, err := a.getDockerCandidate(ctx)
	if err != nil {
		log.Debugf("(attestation/oci) error getting docker candidate: %w", err)
		return err
	}
	if met != nil {
		err := a.setDockerCandidate(met)
		if err != nil {
			log.Debugf("(attestation/oci) error setting docker candidate: %w", err)
			return err
		}
	} else {
		// NOTE: our final attempt here is to try and find the sha256 image digest saved to a file.
		// most tools provide the ability to do this (e.g., docker, podman), and if they don't other manual mechanisms could be
		// established by a user
		dig, err := a.getImageDigestFileCandidate(ctx)
		if err != nil {
			log.Debugf("(attestation/oci) error getting image digest from file: %w", err)
			return err
		}

		trimmed, found := strings.CutPrefix(dig, "sha256:")
		if found == false {
			err := fmt.Errorf("failed to remove prefix from digest")
			log.Debugf("(attestation/oci) %s", err.Error())
			return err
		}
		a.ImageDigest = map[cryptoutil.DigestValue]string{}
		a.ImageDigest[cryptoutil.DigestValue{Hash: crypto.SHA256}] = trimmed
	}

	return nil
}

func (a *Attestor) setDockerCandidate(met *docker.BuildInfo) error {
	if strings.HasPrefix(met.ContainerImageDigest, "sha256:") {
		log.Debugf("(attestation/oci) found image digest '%s'", met.ContainerImageDigest)
		a.ImageDigest = map[cryptoutil.DigestValue]string{}
		log.Debugf("(attestation/oci) removing 'sha256:' prefix from digest '%s'", met.ContainerImageDigest)
		trimmed, found := strings.CutPrefix(met.ContainerImageDigest, "sha256:")
		if found == false {
			err := fmt.Errorf("failed to remove prefix from digest")
			log.Debugf("(attestation/oci) %s", err.Error())
			return err
		}
		log.Debugf("(attestation/oci) setting image digest as '%s'", trimmed)
		a.ImageDigest[cryptoutil.DigestValue{Hash: crypto.SHA256}] = trimmed
	} else {
		log.Warnf("(attestation/oci) found metadata file does not contain image digest of expected format: '%s'", met.ContainerImageDigest)
	}

	if len(met.Provenance.Materials) != 0 {
		a.Materials = []Material{}
		for _, material := range met.Provenance.Materials {
			a.Materials = append(a.Materials, Material{URI: material.URI, Digest: cryptoutil.DigestSet{
				cryptoutil.DigestValue{crypto.SHA256, false, false}: material.Digest.Sha256,
			}})
		}
	}

	// NOTE: we can get the builder architecture information from another attestor
	// if plat := met.Provenance.Invocation.Environment.Platform; plat != "" {
	// 	s := strings.Split(plat, "/")
	// 	if len(s) != 2 {
	// 		log.Warnf("(attestation/oci) docker buildx metadata `invocation.environment.platform` field '%s' not in expected `os/arch` fomat. skipping", plat)
	// 	}
	//
	// 	a.Environment = met.Provenance.Invocation.Environment.Platform
	// }

	log.Debugf("setting image references as '%s'", met.ImageName)
	a.ImageReferences = []string{}
	a.ImageReferences = append(a.ImageReferences, met.ImageName)
	return nil
}

func (a *Attestor) getImageDigestFileCandidate(ctx *attestation.AttestationContext) (string, error) {
	products := ctx.Products()

	for path, product := range products {
		if strings.Contains(sha256MimeType, product.MimeType) {
			f, err := os.ReadFile(filepath.Join(ctx.WorkingDir(), path))
			if err != nil {
				return "", fmt.Errorf("failed to read file %s: %w", path, err)
			}
			return string(f), nil
		}
	}

	return "", nil
}

func (a *Attestor) getDockerCandidate(ctx *attestation.AttestationContext) (*docker.BuildInfo, error) {
	products := ctx.Products()

	if len(products) == 0 {
		return nil, fmt.Errorf("no products to attest")
	}

	//NOTE: it's not ideal to try and parse it without a mime type but the metadata file is completely different depending on how the buildx is executed
	for path, _ := range products {
		var met docker.BuildInfo
		f, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s: %w", path, err)
		}

		err = json.Unmarshal(f, &met)
		if err != nil {
			log.Debugf("(attestation/oci) error parsing file %s as docker metadata file: %w", path, err)
			continue
		}

		log.Info("found image metadata file")

		return &met, nil
	}

	return nil, nil
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	subj := make(map[string]cryptoutil.DigestSet)
	subj[fmt.Sprintf("imagedigest:%s", a.ImageDigest[cryptoutil.DigestValue{Hash: crypto.SHA256}])] = a.ImageDigest

	for _, ir := range a.ImageReferences {
		if hash, err := cryptoutil.CalculateDigestSetFromBytes([]byte(ir), hashes); err == nil {
			subj[fmt.Sprintf("imagereference:%s", ir)] = hash
		} else {
			log.Debugf("(attestation/oci) failed to record github imagereference subject: %w", err)
		}
	}

	for _, m := range a.Materials {
		subj[fmt.Sprintf("materialdigest:%s", m.Digest[cryptoutil.DigestValue{Hash: crypto.SHA256}])] = m.Digest
		if hash, err := cryptoutil.CalculateDigestSetFromBytes([]byte(m.URI), hashes); err == nil {
			subj[fmt.Sprintf("materialuri:%s", m.URI)] = hash
		} else {
			log.Debugf("(attestation/github) failed to record github materialuri subject: %w", err)
		}
	}

	// image tags
	for _, ref := range a.ImageReferences {
		hash, err := cryptoutil.CalculateDigestSetFromBytes([]byte(ref), hashes)
		if err != nil {
			log.Debugf("(attestation/oci) error calculating image reference: %w", err)
			continue
		}
		subj[fmt.Sprintf("imagereference:%s", ref)] = hash
	}

	return subj
}
