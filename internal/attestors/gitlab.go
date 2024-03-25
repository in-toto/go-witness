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
	"github.com/in-toto/go-witness/attestation/gitlab"
	"github.com/in-toto/go-witness/cryptoutil"
)

var (
	_ gitlab.GitLabAttestor = &TestGitLabAttestor{}
)

type TestGitLabAttestor struct {
	gitlabAtt gitlab.GitLabAttestor
}

func (t *TestGitLabAttestor) New() *TestGitLabAttestor {
	att := &gitlab.Attestor{}
	return &TestGitLabAttestor{gitlabAtt: att}
}

func (t *TestGitLabAttestor) Name() string {
	return t.gitlabAtt.Name()
}

func (t *TestGitLabAttestor) Type() string {
	return t.gitlabAtt.Type()
}

func (t *TestGitLabAttestor) RunType() attestation.RunType {
	return t.gitlabAtt.RunType()
}

func (t *TestGitLabAttestor) Attest(ctx *attestation.AttestationContext) error {
	return nil
}

func (t *TestGitLabAttestor) Subjects() map[string]cryptoutil.DigestSet {
	return nil
}

func (t *TestGitLabAttestor) BackRefs() map[string]cryptoutil.DigestSet {
	return nil
}
