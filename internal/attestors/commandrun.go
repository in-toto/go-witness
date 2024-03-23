package attestors

import (
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/commandrun"
	"github.com/in-toto/go-witness/cryptoutil"
)

var (
	_ commandrun.CommandRunAttestor = &TestCommandRunAttestor{}
)

type TestCommandRunAttestor struct {
	comAtt commandrun.CommandRunAttestor
}

func (t *TestCommandRunAttestor) New() *TestCommandRunAttestor {
	att := &commandrun.CommandRun{}
	return &TestCommandRunAttestor{comAtt: att}
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

func (t *TestCommandRunAttestor) Attest(ctx *attestation.AttestationContext) error {
	return nil
}

func (t *TestCommandRunAttestor) CommandRuns() map[string]cryptoutil.DigestSet {
	return nil
}
