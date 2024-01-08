//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aws

import (
	"context"
	"crypto"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/in-toto/go-witness/cryptoutil"
	kms "github.com/in-toto/go-witness/signer/kms"
)

var awsSupportedAlgorithms = []types.CustomerMasterKeySpec{
	types.CustomerMasterKeySpecRsa2048,
	types.CustomerMasterKeySpecRsa3072,
	types.CustomerMasterKeySpecRsa4096,
	types.CustomerMasterKeySpecEccNistP256,
	types.CustomerMasterKeySpecEccNistP384,
	types.CustomerMasterKeySpecEccNistP521,
}

var awsSupportedHashFuncs = []crypto.Hash{
	crypto.SHA256,
	crypto.SHA384,
	crypto.SHA512,
}

// SignerVerifier is a cryptoutil.SignerVerifier that uses the AWS Key Management Service
type SignerVerifier struct {
	client *awsClient
}

// LoadSignerVerifier generates signatures using the specified key object in AWS KMS and hash algorithm.
func LoadSignerVerifier(ctx context.Context, ksp *kms.KMSSignerProvider) (*SignerVerifier, error) {
	a := &SignerVerifier{}

	var err error
	a.client, err = newAWSClient(ctx, ksp)
	if err != nil {
		return nil, err
	}

	return a, nil
}

// NOTE: This might ben all wrong but setting it like so for now
// KeyID returnst the key identifier for the key used by this signer.
func (a *SignerVerifier) KeyID() (string, error) {
	return a.client.keyID, nil
}

// SignMessage signs the provided message using AWS KMS. If the message is provided,
// this method will compute the digest according to the hash function specified
// when the Signer was created.
//
// SignMessage recognizes the following Options listed in order of preference:
//
// - WithContext()
//
// - WithDigest()
//
// - WithCryptoSignerOpts()
//
// All other options are ignored if specified.
func (a *SignerVerifier) Sign(message io.Reader) ([]byte, error) {
	var err error
	ctx := context.Background()
	var digest []byte

	var signerOpts crypto.SignerOpts
	signerOpts, err = a.client.getHashFunc(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting fetching default hash function: %w", err)
	}

	hf := signerOpts.HashFunc()

	digest, _, err = cryptoutil.ComputeDigestForVerifying(message, hf, awsSupportedHashFuncs)
	if err != nil {
		return nil, err
	}

	return a.client.sign(ctx, digest, hf)
}

// PublicKey returns the public key that can be used to verify signatures created by
// this signer. If the caller wishes to specify the context to use to obtain
// the public key, pass option.WithContext(desiredCtx).
//
// All other options are ignored if specified.
func (a *SignerVerifier) Verifier() (cryptoutil.Verifier, error) {
	return a, nil
}

// Bytes returns the bytes of the public key that can be used to verify signatures created by the signer.
func (a *SignerVerifier) Bytes() ([]byte, error) {
	ctx := context.Background()
	p, err := a.client.fetchPublicKey(ctx)
	if err != nil {
		return nil, err
	}

	return cryptoutil.PublicPemBytes(p)
}

// VerifySignature verifies the signature for the given message. Unless provided
// in an option, the digest of the message will be computed using the hash function specified
// when the SignerVerifier was created.
//
// This function returns nil if the verification succeeded, and an error message otherwise.
//
// This function recognizes the following Options listed in order of preference:
//
// - WithContext()
//
// - WithDigest()
//
// - WithRemoteVerification()
//
// - WithCryptoSignerOpts()
//
// All other options are ignored if specified.
func (a *SignerVerifier) Verify(message io.Reader, sig []byte) (err error) {
	ctx := context.Background()
	var digest []byte
	// var remoteVerification bool

	//for _, opt := range opts {
	//	opt.ApplyContext(&ctx)
	//	opt.ApplyDigest(&digest)
	//	opt.ApplyRemoteVerification(&remoteVerification)
	//}

	var signerOpts crypto.SignerOpts
	signerOpts, err = a.client.getHashFunc(ctx)
	if err != nil {
		return fmt.Errorf("getting hash func: %w", err)
	}
	hf := signerOpts.HashFunc()

	digest, _, err = cryptoutil.ComputeDigestForVerifying(message, hf, awsSupportedHashFuncs)
	if err != nil {
		return err
	}

	return a.client.verifyRemotely(ctx, sig, digest)
}

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

func (c cryptoSignerWrapper) Public() crypto.PublicKey {
	ctx := context.Background()

	cmk, err := c.sv.client.getCMK(ctx)
	if err != nil {
		return nil
	}

	return cmk.PublicKey
}

func (c cryptoSignerWrapper) Sign(message io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	//hashFunc := c.hashFunc
	//if opts != nil {
	//	hashFunc = opts.HashFunc()
	//}
	//awsOptions := []signature.SignOption{
	//	options.WithContext(c.ctx),
	//	options.WithDigest(digest),
	//	options.WithCryptoSignerOpts(hashFunc),
	//}

	return c.sv.Sign(message)
}

// CryptoSigner returns a crypto.Signer object that uses the underlying SignerVerifier, along with a crypto.SignerOpts object
// that allows the KMS to be used in APIs that only accept the standard golang objects
func (a *SignerVerifier) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	defaultHf, err := a.client.getHashFunc(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("getting fetching default hash function: %w", err)
	}

	csw := &cryptoSignerWrapper{
		ctx:      ctx,
		sv:       a,
		hashFunc: defaultHf,
		errFunc:  errFunc,
	}

	return csw, defaultHf, nil
}

// SupportedAlgorithms returns the list of algorithms supported by the AWS KMS service
func (*SignerVerifier) SupportedAlgorithms() []string {
	s := make([]string, len(awsSupportedAlgorithms))
	for i := range awsSupportedAlgorithms {
		s[i] = string(awsSupportedAlgorithms[i])
	}
	return s
}

// DefaultAlgorithm returns the default algorithm for the AWS KMS service
func (*SignerVerifier) DefaultAlgorithm() string {
	return string(types.CustomerMasterKeySpecEccNistP256)
}
