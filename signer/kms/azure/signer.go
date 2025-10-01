// Copyright 2025 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package azure

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"io"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/in-toto/go-witness/cryptoutil"
	kms "github.com/in-toto/go-witness/signer/kms"
)

var azureSupportedAlgorithms = []string{
	string(azkeys.SignatureAlgorithmRS256),
	string(azkeys.SignatureAlgorithmRS384),
	string(azkeys.SignatureAlgorithmRS512),
	string(azkeys.SignatureAlgorithmPS256),
	string(azkeys.SignatureAlgorithmPS384),
	string(azkeys.SignatureAlgorithmPS512),
	string(azkeys.SignatureAlgorithmES256),
	string(azkeys.SignatureAlgorithmES256K),
	string(azkeys.SignatureAlgorithmES384),
	string(azkeys.SignatureAlgorithmES512),
}

var azureSupportedHashFuncs = []crypto.Hash{
	crypto.SHA256,
	crypto.SHA384,
	crypto.SHA512,
}

// SignerVerifier is a cryptoutil.SignerVerifier that uses the Azure Key Vault
type SignerVerifier struct {
	reference string
	client    client
	hashFunc  crypto.Hash
}

// LoadSignerVerifier generates signatures using the specified key object in Azure Key Vault and hash algorithm.
func LoadSignerVerifier(ctx context.Context, ksp *kms.KMSSignerProvider) (*SignerVerifier, error) {
	a := &SignerVerifier{
		reference: ksp.Reference,
	}

	var err error
	a.client, err = newAzureClient(ctx, ksp)
	if err != nil {
		return nil, err
	}

	for _, hashFunc := range azureSupportedHashFuncs {
		if hashFunc == ksp.HashFunc {
			a.hashFunc = ksp.HashFunc
		}
	}

	if a.hashFunc == 0 {
		// Default to SHA256 if not specified
		a.hashFunc = crypto.SHA256
	}

	return a, nil
}

// KeyID returns the key identifier for the key used by this signer.
func (a *SignerVerifier) KeyID() (string, error) {
	return a.reference, nil
}

// Sign signs the provided message using Azure Key Vault. If the message is provided,
// this method will compute the digest according to the hash function specified
// when the Signer was created.
func (a *SignerVerifier) Sign(message io.Reader) ([]byte, error) {
	var err error
	ctx := context.TODO()
	var digest []byte

	var signerOpts crypto.SignerOpts
	signerOpts, err = a.client.getHashFunc(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting fetching default hash function: %w", err)
	}

	hf := signerOpts.HashFunc()

	digest, _, err = cryptoutil.ComputeDigest(message, hf, azureSupportedHashFuncs)
	if err != nil {
		return nil, err
	}

	return a.client.sign(ctx, digest, hf)
}

// Verifier returns a cryptoutil.Verifier that can be used to verify signatures created by this signer.
func (a *SignerVerifier) Verifier() (cryptoutil.Verifier, error) {
	return a, nil
}

// Bytes returns the bytes of the public key that can be used to verify signatures created by the signer.
func (a *SignerVerifier) Bytes() ([]byte, error) {
	ctx := context.TODO()
	p, err := a.client.fetchPublicKey(ctx)
	if err != nil {
		return nil, err
	}

	return cryptoutil.PublicPemBytes(p)
}

// Verify verifies the signature for the given message, returning
// nil if the verification succeeded, and an error message otherwise.
func (a *SignerVerifier) Verify(message io.Reader, sig []byte) (err error) {
	ctx := context.TODO()

	return a.client.verify(ctx, bytes.NewReader(sig), message)
}

// SupportedAlgorithms returns the list of algorithms supported by the Azure Key Vault service
func (*SignerVerifier) SupportedAlgorithms() []string {
	return azureSupportedAlgorithms
}

// DefaultAlgorithm returns the default algorithm for the Azure Key Vault service
func (*SignerVerifier) DefaultAlgorithm() string {
	return string(azkeys.SignatureAlgorithmES256)
}
