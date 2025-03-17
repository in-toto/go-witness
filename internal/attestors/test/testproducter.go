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

package attestors

import (
	"github.com/in-toto/go-witness/attestation"
	"github.com/invopop/jsonschema"
)

type TestProducter struct {
	products map[string]attestation.Product
}

func (TestProducter) Name() string {
	return "dummy-products"
}

func (TestProducter) Type() string {
	return "dummy-products"
}

func (TestProducter) RunType() attestation.RunType {
	return attestation.PreMaterialRunType
}

func (TestProducter) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&TestProducter{})
}

func (TestProducter) Attest(ctx *attestation.AttestationContext) error {
	return nil
}

func (t TestProducter) Products() map[string]attestation.Product {
	return t.products
}

func (t *TestProducter) SetProducts(products map[string]attestation.Product) {
	t.products = products
}
