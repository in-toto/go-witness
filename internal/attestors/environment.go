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
	"github.com/in-toto/go-witness/attestation/environment"
	"github.com/invopop/jsonschema"
)

var _ environment.EnvironmentAttestor = &TestEnvironmentAttestor{}

type TestEnvironmentAttestor struct {
	environmentAtt environment.Attestor
}

func NewTestEnvironmentAttestor() *TestEnvironmentAttestor {
	att := environment.New()
	return &TestEnvironmentAttestor{environmentAtt: *att}
}

func (t *TestEnvironmentAttestor) Name() string {
	return t.environmentAtt.Name()
}

func (t *TestEnvironmentAttestor) Type() string {
	return t.environmentAtt.Type()
}

func (t *TestEnvironmentAttestor) RunType() attestation.RunType {
	return t.environmentAtt.RunType()
}

func (t *TestEnvironmentAttestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&t)
}

func (t *TestEnvironmentAttestor) Attest(ctx *attestation.AttestationContext) error {
	return nil
}

func (t *TestEnvironmentAttestor) Data() *environment.Attestor {
	return &t.environmentAtt
}
