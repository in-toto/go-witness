package attestors

import (
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/github"
	"github.com/in-toto/go-witness/cryptoutil"
)

var (
	_ github.GitHubAttestor = &TestGitHubAttestor{}
)

type TestGitHubAttestor struct {
	githubAtt github.GitHubAttestor
}

func (t *TestGitHubAttestor) New() *TestGitHubAttestor {
	att := &github.Attestor{}
	return &TestGitHubAttestor{githubAtt: att}
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

func (t *TestGitHubAttestor) Subjects() map[string]cryptoutil.DigestSet {
	return nil
}

func (t *TestGitHubAttestor) BackRefs() map[string]cryptoutil.DigestSet {
	return nil
}
