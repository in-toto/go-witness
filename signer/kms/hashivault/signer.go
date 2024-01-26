// Copyright 2023 The Witness Contributors
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

package hashivault

import (
	"context"
	"crypto"
	"fmt"
	"io"

	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	kms "github.com/in-toto/go-witness/signer/kms"
)

// Taken from https://www.vaultproject.io/api/secret/transit
// nolint:revive
const (
	AlgorithmECDSAP256 = "ecdsa-p256"
	AlgorithmECDSAP384 = "ecdsa-p384"
	AlgorithmECDSAP521 = "ecdsa-p521"
	AlgorithmED25519   = "ed25519"
	AlgorithmRSA2048   = "rsa-2048"
	AlgorithmRSA3072   = "rsa-3072"
	AlgorithmRSA4096   = "rsa-4096"
)

var hvSupportedAlgorithms = []string{
	AlgorithmECDSAP256,
	AlgorithmECDSAP384,
	AlgorithmECDSAP521,
	AlgorithmED25519,
	AlgorithmRSA2048,
	AlgorithmRSA3072,
	AlgorithmRSA4096,
}

var hvSupportedHashFuncs = []crypto.Hash{
	crypto.SHA224,
	crypto.SHA256,
	crypto.SHA384,
	crypto.SHA512,
	crypto.Hash(0),
}

// SignerVerifier is a cryptoutil.SignerVerifier that uses the AWS Key Management Service
type SignerVerifier struct {
	reference string
	client    *vaultClient
	hashFunc  crypto.Hash
}

// LoadSignerVerifier generates signatures using the specified key object in AWS KMS and hash algorithm.
func LoadSignerVerifier(ctx context.Context, ksp *kms.KMSSignerProvider) (*SignerVerifier, error) {
	h := &SignerVerifier{
		reference: ksp.Reference,
	}

	rpcOpts, err := initRPCOpts()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize RPC options: %w", err)
	}

	h.client, err = newVaultClient(ctx, ksp, rpcOpts)
	if err != nil {
		return nil, err
	}

	for _, hashFunc := range hvSupportedHashFuncs {
		if hashFunc == ksp.HashFunc {
			h.hashFunc = ksp.HashFunc
		}
	}

	if h.hashFunc == 0 {
		return nil, fmt.Errorf("unsupported hash function: %v", ksp.HashFunc)
	}

	return h, nil
}

// NOTE: This might be all wrong but setting it like so for now
//
// KeyID returns the key identifier for the key used by this signer.
func (h *SignerVerifier) KeyID() (string, error) {
	return h.reference, nil
}

// Sign signs the provided message using GCP KMS. If the message is provided,
// this method will compute the digest according to the hash function specified
// when the Signer was created.
func (h *SignerVerifier) Sign(message io.Reader) ([]byte, error) {
	var digest []byte
	var err error
	ctx := context.Background()

	var signerOpts crypto.SignerOpts
	hf := signerOpts.HashFunc()

	digest, _, err = cryptoutil.ComputeDigest(message, hf, hvSupportedHashFuncs)
	if err != nil {
		return nil, err
	}

	return h.client.sign(ctx, digest, hf)
}

// Verifier returns a cryptoutil.Verifier that can be used to verify signatures created by this signer.
func (h *SignerVerifier) Verifier() (cryptoutil.Verifier, error) {
	return h, nil
}

// PublicKey returns the public key that can be used to verify signatures created by
// this signer.
func (h *SignerVerifier) PublicKey(ctx context.Context) (crypto.PublicKey, error) {
	return h.client.public()
}

// Bytes returns the bytes of the public key that can be used to verify signatures created by the signer.
func (h *SignerVerifier) Bytes() ([]byte, error) {
	pub, err := h.client.public()
	if err != nil {
		return nil, err
	}

	return cryptoutil.PublicPemBytes(pub)
}

// VerifySignature verifies the signature for the given message, returning
// nil if the verification succeeded, and an error message otherwise.
func (h *SignerVerifier) Verify(message io.Reader, sig []byte) (err error) {
	var digest []byte
	hf := h.hashFunc
	err = h.client.verify(sig, digest, hf)
	if err != nil {
		log.Info(err.Error())
	}

	return err
}

// SupportedAlgorithms returns the list of algorithms supported by the AWS KMS service
func (h *SignerVerifier) SupportedAlgorithms() (result []string) {
	return hvSupportedAlgorithms
}

// DefaultAlgorithm returns the default algorithm for the GCP KMS service
func (h *SignerVerifier) DefaultAlgorithm() string {
	return AlgorithmECDSAP256
}
