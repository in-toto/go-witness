package dsse

import (
	"fmt"

	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/signature/envelope"

	// Eventually we will migrate to using github.com/securesystemslab/dsse
	// but for now it doesn't support timestamps and intermediates
	idsse "github.com/in-toto/go-witness/dsse"
)

type Envelope struct {
	Envelope *idsse.Envelope
}

func (e *Envelope) Sign(signer *cryptoutil.Signer) error {
	if e.Envelope.PayloadType == "" || e.Envelope.Payload == "" {
		return fmt.Errorf("PayloadType and Payload not populated correctly")
	}

	se, err := idsse.Sign(e.Envelope.PayloadType, []byte(e.Envelope.Payload), idsse.SignWithSigners(*signer))
	if err != nil {
		return err
	}

	e.Envelope = &se

	return nil
}

func (e *Envelope) Verify(v *cryptoutil.Verifier) error {
	_, err := e.Envelope.Verify(idsse.VerifyWithVerifiers(*v))
	if err != nil {
		return err
	}

	return nil
}

func (e *Envelope) Content() (*envelope.EnvelopeContent, error) {
	env := envelope.EnvelopeContent{}
	env.Payload = e.Envelope.Payload
	env.PayloadType = e.Envelope.PayloadType
	for _, sig := range e.Envelope.Signatures {
		s := envelope.SignatureInfo{
			KeyID:         sig.KeyID,
			Signature:     sig.Signature,
			Certificate:   sig.Certificate,
			Intermediates: sig.Intermediates,
		}

		env.Signatures = append(env.Signatures, s)
	}

	return &env, nil
}
