package envelope

import (
	"github.com/in-toto/go-witness/cryptoutil"
)

// Envelope provides basic functions to manipulate signatures.
type Envelope interface {
	// Sign generates and sign the envelope according to the sign request.
	Sign(signer *cryptoutil.Signer) error

	// Verify verifies the envelope and returns its enclosed payload and signer
	// info.
	Verify(pub *cryptoutil.Verifier) error

	// Content returns the payload and signer information of the envelope.
	// Content is trusted only after the successful call to `Verify()`.
	Content() (*EnvelopeContent, error)
}

type EnvelopeContent struct {
	PayloadType string
	Payload     string
	Signatures  []SignatureInfo
}

type SignatureInfo struct {
	KeyID         string   `json:"keyid"`
	Signature     []byte   `json:"sig"`
	Certificate   []byte   `json:"certificate,omitempty"`
	Intermediates [][]byte `json:"intermediates,omitempty"`
}
