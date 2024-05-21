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

func NewOmnitrailAttestor() *OmnitrailAttestor {
	return &OmnitrailAttestor{}
}

type OmnitrailAttestor struct {
	Envelope *ot.Envelope `json:"trail"`
}

// Attest implements attestation.Attestor.
func (o *OmnitrailAttestor) Attest(ctx *attestation.AttestationContext) error {
	trail := ot.NewTrail()
	err := trail.Add(ctx.WorkingDir())
	if err != nil {
		return err
	}
	o.Envelope = trail.Envelope()
	return nil
}

// Name implements attestation.Attestor.
func (o *OmnitrailAttestor) Name() string {
	return Name
}

// RunType implements attestation.Attestor.
func (o *OmnitrailAttestor) RunType() attestation.RunType {
	return RunType
}

// // Schema implements attestation.Attestor.
func (o *OmnitrailAttestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&o)
}

// Type implements attestation.Attestor.
func (o *OmnitrailAttestor) Type() string {
	return Type
}
