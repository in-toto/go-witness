package attestors

import (
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/material"
	"github.com/in-toto/go-witness/cryptoutil"
)

var (
	_ material.MaterialAttestor = &TestMaterialAttestor{}
)

type TestMaterialAttestor struct {
	matAtt material.MaterialAttestor
}

func (t *TestMaterialAttestor) New() *TestMaterialAttestor {
	att := &material.Attestor{}
	return &TestMaterialAttestor{matAtt: att}
}

func (t *TestMaterialAttestor) Name() string {
	return t.matAtt.Name()
}

func (t *TestMaterialAttestor) Type() string {
	return t.matAtt.Type()
}

func (t *TestMaterialAttestor) RunType() attestation.RunType {
	return t.matAtt.RunType()
}

func (t *TestMaterialAttestor) Attest(ctx *attestation.AttestationContext) error {
	return nil
}

func (t *TestMaterialAttestor) Materials() map[string]cryptoutil.DigestSet {
	return nil
}
