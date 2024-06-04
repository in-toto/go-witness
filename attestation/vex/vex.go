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

package vex

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"github.com/invopop/jsonschema"
	vex "github.com/openvex/go-vex/pkg/vex"
)

const (
	Name    = "vex"
	Type    = "https://openvex.dev/ns"
	RunType = attestation.PostProductRunType
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor = &Attestor{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type Attestor struct {
	VEXDocument     vex.VEX              `json:"vexDocument"`
	ReportFile      string               `json:"reportFileName,omitempty"`
	ReportDigestSet cryptoutil.DigestSet `json:"reportDigestSet,omitempty"`
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
	if err := a.getCandidate(ctx); err != nil {
		log.Debugf("(attestation/vex) error getting candidate: %w", err)
		return err
	}

	return nil
}

func (a *Attestor) getCandidate(ctx *attestation.AttestationContext) error {
	products := ctx.Products()

	if len(products) == 0 {
		return fmt.Errorf("no products to attest")
	}

	for path, product := range products {
		newDigestSet, err := cryptoutil.CalculateDigestSetFromFile(path, ctx.Hashes())
		if newDigestSet == nil || err != nil {
			return fmt.Errorf("error calculating digest set from file: %s", path)
		}

		if !newDigestSet.Equal(product.Digest) {
			return fmt.Errorf("integrity error: product digest set does not match candidate digest set")
		}

		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("error opening file: %s", path)
		}

		reportBytes, err := io.ReadAll(f)
		if err != nil {
			return fmt.Errorf("error reading file: %s", path)
		}

		// Check to see if we can unmarshal into VEX type
		if err := json.Unmarshal(reportBytes, &a.VEXDocument); err != nil {
			log.Debugf("(attestation/vex) error unmarshaling VEX document: %w", err)
			continue
		}

		a.ReportFile = path
		a.ReportDigestSet = product.Digest

		return nil
	}
	return fmt.Errorf("no VEX file found")
}
