package attestors

import (
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/git"
	"github.com/in-toto/go-witness/cryptoutil"
)

var (
	_ git.GitAttestor = &TestGitAttestor{}
)

type TestGitAttestor struct {
	gitAtt git.GitAttestor
}

func (t *TestGitAttestor) New() *TestGitAttestor {
	att := &git.Attestor{}
	return &TestGitAttestor{gitAtt: att}
}

func (t *TestGitAttestor) Name() string {
	return t.gitAtt.Name()
}

func (t *TestGitAttestor) Type() string {
	return t.gitAtt.Type()
}

func (t *TestGitAttestor) RunType() attestation.RunType {
	return t.gitAtt.RunType()
}

func (t *TestGitAttestor) Attest(ctx *attestation.AttestationContext) error {
	return nil
}

func (t *TestGitAttestor) Subjects() map[string]cryptoutil.DigestSet {
	return nil
}

func (t *TestGitAttestor) BackRefs() map[string]cryptoutil.DigestSet {
	return nil
}
