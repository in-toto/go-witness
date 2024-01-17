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

package gcp

import (
	"context"
	"crypto"
	"fmt"
	"hash/crc32"
	"io"

	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	kms "github.com/in-toto/go-witness/signer/kms"
)

var gcpSupportedHashFuncs = []crypto.Hash{
	crypto.SHA256,
	crypto.SHA512,
	crypto.SHA384,
}

// SignerVerifier is a cryptoutil.SignerVerifier that uses the AWS Key Management Service
type SignerVerifier struct {
	client   *gcpClient
	hashFunc crypto.Hash
}

// LoadSignerVerifier generates signatures using the specified key object in AWS KMS and hash algorithm.
func LoadSignerVerifier(ctx context.Context, ksp *kms.KMSSignerProvider) (*SignerVerifier, error) {
	g := &SignerVerifier{}

	var err error
	g.client, err = newGCPClient(ctx, ksp)
	if err != nil {
		return nil, err
	}

	for _, hashFunc := range gcpSupportedHashFuncs {
		if hashFunc == ksp.HashFunc {
			g.hashFunc = ksp.HashFunc
		}
	}

	if g.hashFunc == 0 {
		return nil, fmt.Errorf("unsupported hash function: %v", ksp.HashFunc)
	}

	return g, nil
}

// NOTE: This might be all wrong but setting it like so for now
//
// KeyID returns the key identifier for the key used by this signer.
func (g *SignerVerifier) KeyID() (string, error) {
	return g.client.keyID, nil
}

// Sign signs the provided message using GCP KMS. If the message is provided,
// this method will compute the digest according to the hash function specified
// when the Signer was created.
func (g *SignerVerifier) Sign(message io.Reader) ([]byte, error) {
	var err error
	ctx := context.Background()
	var digest []byte

	var signerOpts crypto.SignerOpts
	signerOpts, err = g.client.getHashFunc()
	if err != nil {
		return nil, fmt.Errorf("getting fetching default hash function: %w", err)
	}

	hf := signerOpts.HashFunc()

	digest, _, err = cryptoutil.ComputeDigestForSigning(message, hf, gcpSupportedHashFuncs)
	if err != nil {
		return nil, err
	}

	crc32cHasher := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	_, err = crc32cHasher.Write(digest)
	if err != nil {
		return nil, err
	}

	return g.client.sign(ctx, digest, hf, crc32cHasher.Sum32())
}

// Verifier returns a cryptoutil.Verifier that can be used to verify signatures created by this signer.
func (g *SignerVerifier) Verifier() (cryptoutil.Verifier, error) {
	return g, nil
}

// PublicKey returns the public key that can be used to verify signatures created by
// this signer.
func (g *SignerVerifier) PublicKey(ctx context.Context) (crypto.PublicKey, error) {
	return g.client.public(ctx)
}

// Bytes returns the bytes of the public key that can be used to verify signatures created by the signer.
func (g *SignerVerifier) Bytes() ([]byte, error) {
	ckv, err := g.client.getCKV()
	if err != nil {
		return nil, fmt.Errorf("failed to get KMS key version: %w", err)
	}

	return cryptoutil.PublicPemBytes(ckv.PublicKey)
}

// VerifySignature verifies the signature for the given message, returning
// nil if the verification succeeded, and an error message otherwise.
func (g *SignerVerifier) Verify(message io.Reader, sig []byte) (err error) {
	var digest []byte

	var signerOpts crypto.SignerOpts
	signerOpts, err = g.client.getHashFunc()
	if err != nil {
		return fmt.Errorf("getting hash func: %w", err)
	}
	hf := signerOpts.HashFunc()

	digest, _, err = cryptoutil.ComputeDigestForVerifying(message, hf, gcpSupportedHashFuncs)
	if err != nil {
		return err
	}

	err = g.client.verify(digest, sig)
	if err != nil {
		log.Info(err.Error())
	}

	return err
}

// NOTE:Wondering if this should exist, at least for now
//
// CreateKey attempts to create a new key in Vault with the specified algorithm.
func (a *SignerVerifier) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	return a.client.createKey(ctx, algorithm)
}

type cryptoSignerWrapper struct {
	ctx      context.Context
	hashFunc crypto.Hash
	sv       *SignerVerifier
	errFunc  func(error)
}

func (c *cryptoSignerWrapper) Public() crypto.PublicKey {
	ctx := context.Background()

	pk, err := c.sv.PublicKey(ctx)
	if err != nil && c.errFunc != nil {
		c.errFunc(err)
	}
	return pk
}

func (c *cryptoSignerWrapper) Sign(message io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil {
		c.hashFunc = opts.HashFunc()
	}

	return c.sv.Sign(message)
}

// CryptoSigner returns a crypto.Signer object that uses the underlying SignerVerifier, along with a crypto.SignerOpts object
// that allows the KMS to be used in APIs that only accept the standard golang objects
func (g *SignerVerifier) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	defaultHf, err := g.client.getHashFunc()
	if err != nil {
		return nil, nil, fmt.Errorf("getting fetching default hash function: %w", err)
	}

	csw := &cryptoSignerWrapper{
		ctx:      ctx,
		sv:       g,
		hashFunc: defaultHf,
		errFunc:  errFunc,
	}

	return csw, defaultHf, nil
}

// SupportedAlgorithms returns the list of algorithms supported by the AWS KMS service
func (*SignerVerifier) SupportedAlgorithms() (result []string) {
	for k := range algorithmMap {
		result = append(result, k)
	}
	return
}

// DefaultAlgorithm returns the default algorithm for the GCP KMS service
func (g *SignerVerifier) DefaultAlgorithm() string {
	return AlgorithmECDSAP256SHA256
}
