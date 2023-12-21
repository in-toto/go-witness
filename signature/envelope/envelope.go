package envelope

import (
	"github.com/in-toto/go-witness/cryptoutil"
	idsse "github.com/in-toto/go-witness/dsse"
)

// Envelope provides basic functions to manipulate signatures.
type Envelope interface {
	// Sign signs the pre-generated envelope with relevant fields already populated.
	Sign(signer *cryptoutil.Signer, opts ...EnvelopeOption) error

	// Verify verifies the envelope.
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

type EnvelopeOptions struct {
	Timestampers []idsse.Timestamper
}

type EnvelopeOption func(ro *EnvelopeOptions)

func WithTimestampers(timestampers []idsse.Timestamper) EnvelopeOption {
	return func(eo *EnvelopeOptions) {
		eo.Timestampers = timestampers
	}
}
