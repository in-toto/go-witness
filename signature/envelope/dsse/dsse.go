package dsse

import (
	"crypto"
	"fmt"

	"github.com/in-toto/go-witness/cryptoutil"
	// Eventually we will migrate to using github.com/securesystemslab/dsse
	// but for now it doesn't support timestamps and intermediates
	idsse "github.com/in-toto/go-witness/dsse"
)

type DSSEEnvelope struct {
	Envelope *idsse.Envelope
}

func (e *DSSEEnvelope) Sign(signer *crypto.Signer, opts ...cryptoutil.SignerOption) (interface{}, error) {
	if e.Envelope.PayloadType == "" || e.Envelope.Payload == "" {
		return nil, fmt.Errorf("PayloadType and Payload not populated correctly")
	}

	s, err := cryptoutil.NewSigner(signer, opts...)
	if err != nil {
		return nil, err
	}

	se, err := idsse.Sign(e.Envelope.PayloadType, []byte(e.Envelope.Payload), idsse.SignWithSigners(s))
	if err != nil {
		return nil, err
	}

	return se, nil
}

func (e *DSSEEnvelope) Verify(pub *crypto.PublicKey, opts ...cryptoutil.VerifierOption) (interface{}, error) {
	v, err := cryptoutil.NewVerifier(pub, opts...)
	if err != nil {
		return nil, err
	}

	ve, err := e.Envelope.Verify(idsse.VerifyWithVerifiers(v))
	if err != nil {
		return nil, err
	}

	return ve, nil
}

func (e *DSSEEnvelope) Content() (interface{}, error)
