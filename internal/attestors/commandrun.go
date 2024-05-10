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
	"github.com/in-toto/go-witness/attestation/commandrun"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/invopop/jsonschema"
)

var _ commandrun.CommandRunAttestor = &TestCommandRunAttestor{}

type TestCommandRunAttestor struct {
	comAtt commandrun.CommandRun
}

func NewTestCommandRunAttestor() *TestCommandRunAttestor {
	att := commandrun.New()
	return &TestCommandRunAttestor{comAtt: *att}
}

func (t *TestCommandRunAttestor) Name() string {
	return t.comAtt.Name()
}

func (t *TestCommandRunAttestor) Type() string {
	return t.comAtt.Type()
}

func (t *TestCommandRunAttestor) RunType() attestation.RunType {
	return t.comAtt.RunType()
}

func (t *TestCommandRunAttestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&t)
}

func (t *TestCommandRunAttestor) Attest(ctx *attestation.AttestationContext) error {
	return nil
}

func (t *TestCommandRunAttestor) Data() *commandrun.CommandRun {
	return &t.comAtt
}

func (t *TestCommandRunAttestor) CommandRuns() map[string]cryptoutil.DigestSet {
	return nil
}
