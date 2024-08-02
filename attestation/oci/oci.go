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
	"archive/tar"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"os"
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
	ImageID         cryptoutil.DigestSet `json:"imageid"`
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

func (m *Manifest) getDockerImageID(ctx *attestation.AttestationContext, tarFilePath string) (cryptoutil.DigestSet, error) {
	tarFile, err := os.Open(tarFilePath)
	if err != nil {
		return nil, err
	}
	defer tarFile.Close()

	tarReader := tar.NewReader(tarFile)
	for {
		h, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.FileInfo().IsDir() {
			continue
		}

		if h.Name == m.Config {

			b := make([]byte, h.Size)
			_, err := tarReader.Read(b)
			if err != nil && err != io.EOF {
				return nil, err
			}

			imageID, err := cryptoutil.CalculateDigestSetFromBytes(b, ctx.Hashes())
			if err != nil {
				log.Debugf("(attestation/oci) error calculating image id: %w", err)
				return nil, err
			}

			return imageID, nil
		}
	}
	return nil, fmt.Errorf("could not find config in tar file")
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
		log.Debugf("(attestation/oci) error getting candidate: %w", err)
		return err
	}

	if met != nil {
		a.ImageDigest = map[cryptoutil.DigestValue]string{}
		a.ImageDigest[cryptoutil.DigestValue{Hash: crypto.SHA256}] = met.ContainerImageDigest
		fmt.Println("setting image digest as", met.ContainerImageDigest)
		fmt.Println("setting image references as", met.ImageName)
		a.ImageReferences = []string{}
		a.ImageReferences = append(a.ImageReferences, met.ImageName)
	}

	return nil
}

func (a *Attestor) getDockerCandidate(ctx *attestation.AttestationContext) (*docker.BuildInfo, error) {
	products := ctx.Products()

	if len(products) == 0 {
		return nil, fmt.Errorf("no products to attest")
	}

	//NOTE: it's not ideal to try and parse it without a mime type but the metadata file is completely different depending on how the buildx is executed
	for path, product := range products {
		fmt.Println("inspecting", path)
		if strings.Contains(sha256MimeType, product.MimeType) {
			log.Info("found image id")
			f, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("failed to read file %s", path)
			}

			a.ImageID = map[cryptoutil.DigestValue]string{}
			a.ImageID[cryptoutil.DigestValue{Hash: crypto.SHA256}] = string(f)
			continue
		}

		var met docker.BuildInfo

		f, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s", path)
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

// TODO Needs finished, some of these are wrongly configured
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	subj := make(map[string]cryptoutil.DigestSet)
	subj[fmt.Sprintf("imagedigest:%s", a.ImageDigest[cryptoutil.DigestValue{Hash: crypto.SHA256}])] = a.ImageDigest
	subj[fmt.Sprintf("imageid:%s", a.ImageID[cryptoutil.DigestValue{Hash: crypto.SHA256}])] = a.ImageID

	for _, ir := range a.ImageReferences {
		if hash, err := cryptoutil.CalculateDigestSetFromBytes([]byte(ir), hashes); err == nil {
			subj[fmt.Sprintf("imagereference:%s", ir)] = hash
		} else {
			log.Debugf("(attestation/oci) failed to record github imagereference subject: %w", err)
		}
	}

	for _, m := range a.Materials {
		subj[fmt.Sprintf("materialdigest:%s", m.Digest)] = m.Digest
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
