package cose

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/signature/envelope"
	cose "github.com/veraison/go-cose"
)

type Envelope struct {
	Envelope *cose.Sign1Message
}

// NewEnvelope creates a new envelope from specified payload type and non-base64 encoded payload
func NewEnvelope(payloadType string, payload []byte) (*Envelope, error) {
	// simple if statement to detect if payload is base64 encoded
	// NOTE: not sure if this is helpful
	if _, err := base64.StdEncoding.DecodeString(string(payload)); err == nil {
		return nil, fmt.Errorf("please supply payload as a non-base64 encoded byte array")
	}

	// create message header
	return &Envelope{
		Envelope: &cose.Sign1Message{
			Headers: cose.Headers{
				Protected: cose.ProtectedHeader{
					cose.HeaderLabelContentType: payloadType,
				},
			},

			Payload: payload,
		},
	}, nil
}

func (e *Envelope) Sign(signer *cryptoutil.Signer, opts ...envelope.EnvelopeOption) error {
	// create an io.Reader for a random string
	alg, err := getSignerAlg(*signer)
	if err != nil {
		return err
	}

	// we need to set the algorithm in the protected header
	e.Envelope.Headers.Protected[cose.HeaderLabelAlgorithm] = alg

	s, err := (*signer).Signer()
	if err != nil {
		return err
	}

	csigner, err := cose.NewSigner(alg, s)
	if err != nil {
		return err
	}

	err = e.Envelope.Sign(rand.Reader, nil, csigner)
	if err != nil {
		return err
	}

	return nil
}

func (e *Envelope) Content() (*envelope.EnvelopeContent, error) {
	return nil, nil
}

func (e *Envelope) Verify(v *cryptoutil.Verifier) error {
	return nil
}

// NOTE: Don't like embedded switch statements, but not sure what else I can do
func getSignerAlg(signer cryptoutil.Signer) (cose.Algorithm, error) {
	alg, hash := signer.Algorithm()
	switch alg {
	case x509.ECDSA:
		switch hash {
		case crypto.SHA256:
			return cose.AlgorithmES256, nil
		case crypto.SHA384:
			return cose.AlgorithmES384, nil
		case crypto.SHA512:
			return cose.AlgorithmES512, nil
		default:
			return cose.Algorithm(-1), fmt.Errorf("unsupported hash algorithm: %v", hash)
		}
	case x509.RSA:
		switch hash {
		case crypto.SHA256:
			return cose.AlgorithmPS256, nil
		case crypto.SHA384:
			return cose.AlgorithmPS384, nil
		case crypto.SHA512:
			return cose.AlgorithmPS512, nil
		default:
			return cose.Algorithm(-1), fmt.Errorf("unsupported hash algorithm: %v", hash)
		}
	case x509.Ed25519:
		return cose.AlgorithmEd25519, nil
	default:
		return cose.Algorithm(-1), fmt.Errorf("unsupported algorithm: %v", alg)
	}
}
