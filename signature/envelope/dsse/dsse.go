package dsse

import (
	"encoding/base64"
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

// NewEnvelope creates a new envelope from specified payload type and non-base64 encoded payload
func NewEnvelope(payloadType string, payload []byte) (*Envelope, error) {
	// simple if statement to detect if payload is base64 encoded
	if _, err := base64.StdEncoding.DecodeString(string(payload)); err == nil {
		return nil, fmt.Errorf("please supply payload as a non-base64 encoded byte array")
	}
	e := idsse.Envelope{}
	e.PayloadType = payloadType
	e.Payload = string(payload)
	return &Envelope{Envelope: &e}, nil
}

func (e *Envelope) Sign(signer *cryptoutil.Signer, opts ...envelope.EnvelopeOption) error {
	so := envelope.EnvelopeOptions{}

	for _, opt := range opts {
		opt(&so)
	}

	if e.Envelope.PayloadType == "" || e.Envelope.Payload == "" {
		return fmt.Errorf("PayloadType and Payload not populated correctly")
	}

	se, err := idsse.Sign(e.Envelope.PayloadType, []byte(e.Envelope.Payload), idsse.SignWithSigners(*signer), idsse.SignWithTimestampers(so.Timestampers...))
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
