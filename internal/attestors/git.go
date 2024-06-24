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
	"github.com/in-toto/go-witness/attestation/git"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/invopop/jsonschema"
)

var _ git.GitAttestor = &TestGitAttestor{}

type TestGitAttestor struct {
	gitAtt git.Attestor
}

func NewTestGitAttestor() *TestGitAttestor {
	att := git.New()
	return &TestGitAttestor{gitAtt: *att}
}

func (t *TestGitAttestor) Name() string {
	return t.gitAtt.Name()
}

func (t *TestGitAttestor) Type() attestation.TypeSet {
	return t.gitAtt.Type()
}

func (t *TestGitAttestor) RunType() attestation.RunType {
	return t.gitAtt.RunType()
}

func (t *TestGitAttestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&t)
}

func (t *TestGitAttestor) Attest(ctx *attestation.AttestationContext) error {
	return nil
}

func (t *TestGitAttestor) Data() *git.Attestor {
	return &t.gitAtt
}

func (t *TestGitAttestor) Subjects() map[string]cryptoutil.DigestSet {
	return nil
}

func (t *TestGitAttestor) BackRefs() map[string]cryptoutil.DigestSet {
	return nil
}
