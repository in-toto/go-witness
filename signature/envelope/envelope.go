package envelope

import (
	"github.com/in-toto/go-witness/cryptoutil"
	idsse "github.com/in-toto/go-witness/dsse"
)

// Envelope provides basic functions to manipulate signatures.
type Envelope interface {
	// Sign signs the pre-generated envelope with relevant fields already populated.
	Sign(signer *cryptoutil.Signer, opts ...EnvelopeOption) error

	// Verify verifies the envelope against the public key verifier in the input.
	Verify(pub *cryptoutil.Verifier) error

	// Content returns the payload and signer information of the envelope.
	// Content is trusted only after the successful call to `Verify()`.
	Content() (*EnvelopeContent, error)
}

// EnvelopeContent holds contents of the envelope for the purpose reuse in other operations.
type EnvelopeContent struct {
	// Payload Type is a string that uniquely and unambiguously identifies how to interpret the payload.
	PayloadType string
	// Payload is the base64 encoded data that is signed.
	Payload string
	// Signatures is a list of signatures that were generated against the payload.
	Signatures []SignatureInfo
}

// SignatureInfo holds the signature itself, as well as any other information that may be needed in other operations.
type SignatureInfo struct {
	// KeyID is the indentifier of the key that was used to sign the payload (sha256 hash of the public key).
	KeyID string `json:"keyid"`

	// Signature is the signature that was generated against the payload.
	Signature []byte `json:"sig"`

	// Certificate is the leaf certificate of the signing key.
	Certificate []byte `json:"certificate,omitempty"`

	// Root is the root certificate that signed the leaf and Intermediate certificates.
	Root [][]byte

	// Intermediates is the list of intermediate certificates that are associated with the signing key.
	Intermediates [][]byte `json:"intermediates,omitempty"`
}

// EnvelopeOptions holds the options that can be passed to the Envelope.Sign() function.
type EnvelopeOptions struct {
	// Timestampers is a list of the timestamp authorities that will be used to timestamp the payload.
	Timestampers []idsse.Timestamper
}

// EnvelopeOption defines a function that can be used as an input to Envelope.Sign() for the purpose of passing in options.
type EnvelopeOption func(ro *EnvelopeOptions)

// WithTimestampers returns an EnvelopeOption that will set the timestampers field of the EnvelopeOptions.
func WithTimestampers(timestampers []idsse.Timestamper) EnvelopeOption {
	return func(eo *EnvelopeOptions) {
		eo.Timestampers = timestampers
	}
}
