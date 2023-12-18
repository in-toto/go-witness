package dsse

import (
	"crypto"
	"fmt"

	"github.com/in-toto/go-witness/cryptoutil"
	idsse "github.com/in-toto/go-witness/dsse"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

type DSSEEnvelope struct {
	Envelope *dsse.Envelope
}

func (e *DSSEEnvelope) Sign(signer *crypto.Signer, opts ...cryptoutil.SignerOption) (interface{}, error) {
	if e.Envelope.PayloadType == "" || e.Envelope.Payload == "" {
		return nil, fmt.Errorf("PayloadType and Payload not populated correctly")
	}

	s, err := cryptoutil.NewSigner(signer)
	if err != nil {
		return nil, err
	}

	v, err := cryptoutil.NewVerifier(signer)
	if err != nil {
		return nil, err
	}

	sv := cryptoutil.SignerVerifier{
		Signer:   s,
		Verifier: v,
	}

	se, err := idsse.Sign(e.Envelope.PayloadType, []byte(e.Envelope.Payload), idsse.SignWithSigners(sv.Signer))
	if err != nil {
		return nil, err
	}

	return se, nil
}
