package attestors

import (
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/product"
	"github.com/in-toto/go-witness/cryptoutil"
)

var (
	_ product.ProductAttestor = &TestProductAttestor{}
)

type TestProductAttestor struct {
	prodAtt product.ProductAttestor
}

func (t *TestProductAttestor) New() *TestProductAttestor {
	att := &product.Attestor{}
	return &TestProductAttestor{prodAtt: att}
}

func (t *TestProductAttestor) Name() string {
	return t.prodAtt.Name()
}

func (t *TestProductAttestor) Type() string {
	return t.prodAtt.Type()
}

func (t *TestProductAttestor) RunType() attestation.RunType {
	return t.prodAtt.RunType()
}

func (t *TestProductAttestor) Attest(ctx *attestation.AttestationContext) error {
	return nil
}

func (t *TestProductAttestor) Subjects() map[string]cryptoutil.DigestSet {
	return nil
}

func (t *TestProductAttestor) Products() map[string]attestation.Product {
	return nil
}
