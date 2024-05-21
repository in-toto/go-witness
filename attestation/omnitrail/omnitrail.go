package omnitrail

import (
	ot "github.com/fkautz/omnitrail-go"
	"github.com/in-toto/go-witness/attestation"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "omnitrail"
	Type    = "https://witness.dev/attestations/omnitrail/v0.1"
	RunType = attestation.PreMaterialRunType
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return NewOmnitrailAttestor()
	})
}

type Attestor struct {
	Envelope *ot.Envelope `json:"Envelope"`
}

func NewOmnitrailAttestor() *Attestor {
	return &Attestor{}
}

// Attest implements attestation.Attestor.
func (o *Attestor) Attest(ctx *attestation.AttestationContext) error {
	trail := ot.NewTrail()
	err := trail.Add(ctx.WorkingDir())
	if err != nil {
		return err
	}
	o.Envelope = trail.Envelope()
	return nil
}

// Name implements attestation.Attestor.
func (o *Attestor) Name() string {
	return Name
}

// RunType implements attestation.Attestor.
func (o *Attestor) RunType() attestation.RunType {
	return RunType
}

// // Schema implements attestation.Attestor.
func (o *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&o)
}

// Type implements attestation.Attestor.
func (o *Attestor) Type() string {
	return Type
}
