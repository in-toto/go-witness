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
	"github.com/in-toto/go-witness/attestation/github"
	"github.com/in-toto/go-witness/attestation/jwt"
	"github.com/in-toto/go-witness/cryptoutil"
)

var (
	_ github.GitHubAttestor = &TestGitHubAttestor{}
)

type TestGitHubAttestor struct {
	githubAtt github.Attestor
}

func NewTestGitHubAttestor() *TestGitHubAttestor {
	att := github.New()
	att.JWT = jwt.New()
	return &TestGitHubAttestor{githubAtt: *att}
}

func (t *TestGitHubAttestor) Name() string {
	return t.githubAtt.Name()
}

func (t *TestGitHubAttestor) Type() string {
	return t.githubAtt.Type()
}

func (t *TestGitHubAttestor) RunType() attestation.RunType {
	return t.githubAtt.RunType()
}

func (t *TestGitHubAttestor) Attest(ctx *attestation.AttestationContext) error {
	return nil
}

func (t *TestGitHubAttestor) Data() *github.Attestor {
	return &t.githubAtt
}

func (t *TestGitHubAttestor) Subjects() map[string]cryptoutil.DigestSet {
	return nil
}

func (t *TestGitHubAttestor) BackRefs() map[string]cryptoutil.DigestSet {
	return nil
}
