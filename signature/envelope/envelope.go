package envelope

import (
	"crypto"

	"github.com/in-toto/go-witness/cryptoutil"
)

// Envelope provides basic functions to manipulate signatures.
type Envelope interface {
	// Sign generates and sign the envelope according to the sign request.
	Sign(signer *crypto.Signer, opts ...cryptoutil.SignerOption) (interface{}, error)

	// Verify verifies the envelope and returns its enclosed payload and signer
	// info.
	Verify(pub *crypto.PublicKey, opts ...cryptoutil.VerifierOption) (interface{}, error)

	// Content returns the payload and signer information of the envelope.
	// Content is trusted only after the successful call to `Verify()`.
	Content() ([]byte, error)
}
