package testproducter

import (
	"github.com/in-toto/go-witness/attestation"
	"github.com/invopop/jsonschema"
)

type TestProducter struct {
	products map[string]attestation.Product
}

func (TestProducter) Name() string {
	return "dummy-products"
}

func (TestProducter) Type() string {
	return "dummy-products"
}

func (TestProducter) RunType() attestation.RunType {
	return attestation.PreMaterialRunType
}

func (TestProducter) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&TestProducter{})
}

func (TestProducter) Attest(ctx *attestation.AttestationContext) error {
	return nil
}

func (t TestProducter) Products() map[string]attestation.Product {
	return t.products
}

func (t *TestProducter) SetProducts(products map[string]attestation.Product) {
	t.products = products
}
