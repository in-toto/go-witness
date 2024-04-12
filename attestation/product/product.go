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

package product

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/gabriel-vasile/mimetype"
	"github.com/gobwas/glob"
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/commandrun"
	"github.com/in-toto/go-witness/attestation/file"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/registry"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "product"
	Type    = "https://witness.dev/attestations/product/v0.2"
	RunType = attestation.ProductRunType

	defaultIncludeGlob = "*"
	defaultExcludeGlob = ""
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
	_ attestation.Producer  = &Attestor{}
)

type ProductAttestor interface {
	// Attestor
	Name() string
	Type() string
	RunType() attestation.RunType
	Attest(ctx *attestation.AttestationContext) error

	// Subjector
	Subjects() map[string]cryptoutil.DigestSet

	// Producter
	Products() map[string]attestation.Product
}

func init() {
	attestation.RegisterAttestation(ProductName, ProductType, ProductRunType, func() attestation.Attestor { return New() },
		registry.StringConfigOption(
			"include-glob",
			"Pattern to use when recording products. Files that match this pattern will be included as subjects on the attestation.",
			defaultIncludeGlob,
			func(a attestation.Attestor, includeGlob string) (attestation.Attestor, error) {
				prodAttestor, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a product attestor", a)
				}

				WithIncludeGlob(includeGlob)(prodAttestor)
				return prodAttestor, nil
			},
		),
		registry.StringConfigOption(
			"exclude-glob",
			"Pattern to use when recording products. Files that match this pattern will be excluded as subjects on the attestation.",
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
	products            map[string]attestation.Product
	baseArtifacts       map[string]cryptoutil.DigestSet
	includeGlob         string
	compiledIncludeGlob glob.Glob
	excludeGlob         string
	compiledExcludeGlob glob.Glob
}

<<<<<<< HEAD
func fromDigestMap(workingDir string, digestMap map[string]cryptoutil.DigestSet) map[string]attestation.Product {
=======
type attestorJson struct {
	Products map[string]attestation.Product `json:"products"`
	Configuration attestorConfiguration `json:"configuration"`
}

type attestorConfiguration struct {
	IncludeGlob         string `json:"includeGlob"`
	ExcludeGlob         string `json:"excludeGlob"`
}

func fromDigestMap(digestMap map[string]cryptoutil.DigestSet) map[string]attestation.Product {
>>>>>>> 3ae6278 (fix: Adjust attestation output to include attestor configuration.)
	products := make(map[string]attestation.Product)
	for fileName, digestSet := range digestMap {
		filePath := filepath.Join(workingDir, fileName)
		mimeType, err := getFileContentType(filePath)
		if err != nil {
			mimeType = "unknown"
		}

		products[fileName] = attestation.Product{
			MimeType: mimeType,
			Digest:   digestSet,
		}
	}

	return products
}

func (a *Attestor) Name() string {
	return ProductName
}

func (a *Attestor) Type() string {
	return ProductType
}

func (a *Attestor) RunType() attestation.RunType {
	return ProductRunType
}

func New(opts ...Option) *Attestor {
	a := &Attestor{
		includeGlob: defaultIncludeGlob,
		excludeGlob: defaultExcludeGlob,
	}

	for _, opt := range opts {
		opt(a)
	}

	return a
}

func (a *Attestor) Schema() *jsonschema.Schema {
	// NOTE: This isn't ideal. For some reason the reflect function is return an empty schema when passing in `p`
	// TODO: Fix this later
	return jsonschema.Reflect(struct {
		Products map[string]attestation.Product
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

	a.baseArtifacts = ctx.Materials()

	processWasTraced := false
	openedFileSet := map[string]bool{}

	for _, completedAttestor := range ctx.CompletedAttestors() {
		attestor := completedAttestor.Attestor
		if commandRunAttestor, ok := attestor.(*commandrun.CommandRun); ok && commandRunAttestor.TracingEnabled() {
			processWasTraced = true

			for _, process := range commandRunAttestor.Processes {
				for fname := range process.OpenedFiles {
					openedFileSet[fname] = true
				}
			}
		}
	}

	products, err := file.RecordArtifacts(ctx.WorkingDir(), a.baseArtifacts, ctx.Hashes(), map[string]struct{}{}, processWasTraced, openedFileSet, compiledIncludeGlob, compiledExcludeGlob)
	if err != nil {
		return err
	}

	a.products = fromDigestMap(ctx.WorkingDir(), products)
	return nil
}

func (a *Attestor) MarshalJSON() ([]byte, error) {
	output := attestorJson{
		Products: a.products,
		Configuration: attestorConfiguration{
			IncludeGlob: a.includeGlob,
			ExcludeGlob: a.excludeGlob,
		},
	}

	return json.Marshal(output)
}

func (a *Attestor) UnmarshalJSON(data []byte) error {
	attestation := attestorJson{
		Products: make(map[string]attestation.Product),
	}
	if err := json.Unmarshal(data, &attestation); err != nil {
		return err
	}

	a.products = attestation.Products
	a.includeGlob = attestation.Configuration.IncludeGlob
	a.excludeGlob = attestation.Configuration.ExcludeGlob
	return nil
}

func (a *Attestor) Products() map[string]attestation.Product {
	return a.products
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	subjects := make(map[string]cryptoutil.DigestSet)
	for productName, product := range a.products {

		includeSubject := true
		if a.compiledExcludeGlob != nil && a.compiledExcludeGlob.Match(productName) {
			includeSubject = false
		}
		if a.compiledIncludeGlob != nil && a.compiledIncludeGlob.Match(productName) {
			includeSubject = true
		}

		if includeSubject {
			subjects[fmt.Sprintf("file:%v", productName)] = product.Digest
		}
	}

	return subjects
}

func getFileContentType(fileName string) (string, error) {
	// Add SPDX JSON detector
	mimetype.Lookup("application/json").Extend(func(buf []byte, limit uint32) bool {
		return bytes.HasPrefix(buf, []byte(`{"spdxVersion":"SPDX-`))
	}, "application/spdx+json", ".spdx.json")

	// Add CycloneDx JSON detector
	mimetype.Lookup("application/json").Extend(func(buf []byte, limit uint32) bool {
		return bytes.HasPrefix(buf, []byte(`{"$schema":"http://cyclonedx.org/schema/bom-`))
	}, "application/vnd.cyclonedx+json", ".cdx.json")

	// Add CycloneDx XML detector
	mimetype.Lookup("text/xml").Extend(func(buf []byte, limit uint32) bool {
		return bytes.HasPrefix(buf, []byte(`<?xml version="1.0" encoding="UTF-8"?><bom xmlns="http://cyclonedx.org/schema/bom/`))
	}, "application/vnd.cyclonedx+xml", ".cdx.xml")

	// Add Vex JSON detector
	mimetype.Lookup("application/json").Extend(func(buf []byte, limit uint32) bool {
		return bytes.HasPrefix(buf, []byte(`{"@context":"https://openvex.dev/ns`))
	}, "application/vex+json", ".vex.json")

	contentType, err := mimetype.DetectFile(fileName)
	if err != nil {
		return "", err
	}

	return contentType.String(), nil
}
