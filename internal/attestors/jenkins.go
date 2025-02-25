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
	"github.com/in-toto/go-witness/attestation/jenkins"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/invopop/jsonschema"
)

var _ jenkins.JenkinsAttestor = &TestJenkinsAttestor{}

type TestJenkinsAttestor struct {
	jenkinsAtt jenkins.Attestor
}

func NewTestJenkinsAttestor() *TestJenkinsAttestor {
	att := jenkins.Attestor{}
	return &TestJenkinsAttestor{jenkinsAtt: att}
}

func (t *TestJenkinsAttestor) Name() string {
	return t.jenkinsAtt.Name()
}

func (t *TestJenkinsAttestor) Type() string {
	return t.jenkinsAtt.Type()
}

func (t *TestJenkinsAttestor) RunType() attestation.RunType {
	return t.jenkinsAtt.RunType()
}

func (t *TestJenkinsAttestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&t)
}

func (t *TestJenkinsAttestor) Attest(ctx *attestation.AttestationContext) error {
	return nil
}

func (t *TestJenkinsAttestor) Data() *jenkins.Attestor {
	return &t.jenkinsAtt
}

func (t *TestJenkinsAttestor) Subjects() map[string]cryptoutil.DigestSet {
	return nil
}

func (t *TestJenkinsAttestor) BackRefs() map[string]cryptoutil.DigestSet {
	return nil
}
