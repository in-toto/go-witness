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
	"github.com/in-toto/go-witness/attestation/material"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/invopop/jsonschema"
)

var _ material.MaterialAttestor = &TestMaterialAttestor{}

type TestMaterialAttestor struct {
	matAtt    *material.Attestor
	materials map[string]cryptoutil.DigestSet
}

func NewTestMaterialAttestor() *TestMaterialAttestor {
	att := material.New()
	mat := make(map[string]cryptoutil.DigestSet)
	return &TestMaterialAttestor{matAtt: att, materials: mat}
}

func (t *TestMaterialAttestor) Name() string {
	return t.matAtt.Name()
}

func (t *TestMaterialAttestor) Type() string {
	return t.matAtt.Type()
}

func (t *TestMaterialAttestor) RunType() attestation.RunType {
	return t.matAtt.RunType()
}

func (t *TestMaterialAttestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&t)
}

func (t *TestMaterialAttestor) Attest(ctx *attestation.AttestationContext) error {
	return nil
}

func (t *TestMaterialAttestor) Materials() map[string]cryptoutil.DigestSet {
	return t.materials
}

func (t *TestMaterialAttestor) SetMaterials(mats map[string]cryptoutil.DigestSet) {
	t.materials = mats
}
