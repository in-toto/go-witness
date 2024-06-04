// Copyright 2024 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package attestors

import (
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/product"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/invopop/jsonschema"
)

var _ product.ProductAttestor = &TestProductAttestor{}

type TestProductAttestor struct {
	prodAtt product.ProductAttestor
}

func NewTestProductAttestor() *TestProductAttestor {
	att := product.New()
	return &TestProductAttestor{prodAtt: att}
}

func (t *TestProductAttestor) Name() string {
	return t.prodAtt.Name()
}

func (t *TestProductAttestor) Type() string {
	return t.prodAtt.Type()
}

func (t *TestProductAttestor) RunType() attestation.RunType {
	return t.prodAtt.RunType()
}

func (t *TestProductAttestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&t)
}

func (t *TestProductAttestor) Attest(ctx *attestation.AttestationContext) error {
	return nil
}

func (t *TestProductAttestor) Subjects() map[string]cryptoutil.DigestSet {
	return nil
}

func (t *TestProductAttestor) Products() map[string]attestation.Product {
	return nil
}
