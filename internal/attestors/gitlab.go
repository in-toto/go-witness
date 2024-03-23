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
