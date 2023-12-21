// Copyright 2021 The Witness Contributors
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

package cryptoutil

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
)

type ErrVerifyFailed struct{}

func (e ErrVerifyFailed) Error() string {
	return "verification failed"
}

type ECDSASigner struct {
	priv *ecdsa.PrivateKey
	hash crypto.Hash
}

func NewECDSASigner(priv *ecdsa.PrivateKey, hash crypto.Hash) *ECDSASigner {
	return &ECDSASigner{priv, hash}
}

func (s *ECDSASigner) KeyID() (string, error) {
	return GeneratePublicKeyID(&s.priv.PublicKey, s.hash)
}

func (s *ECDSASigner) Algorithm() (x509.PublicKeyAlgorithm, crypto.Hash) {
	return x509.ECDSA, s.hash
}

func (s *ECDSASigner) Signer() (crypto.Signer, error) {
	return s.priv, nil
}

func (s *ECDSASigner) Sign(ctx context.Context, data []byte) ([]byte, error) {
	digest, err := DigestBytes(data, s.hash)
	if err != nil {
		return nil, err
	}

	return ecdsa.SignASN1(rand.Reader, s.priv, digest)
}

func (s *ECDSASigner) Verifier() (Verifier, error) {
	return NewECDSAVerifier(&s.priv.PublicKey, s.hash), nil
}

type ECDSAVerifier struct {
	pub  *ecdsa.PublicKey
	hash crypto.Hash
}

func NewECDSAVerifier(pub *ecdsa.PublicKey, hash crypto.Hash) *ECDSAVerifier {
	return &ECDSAVerifier{pub, hash}
}

func (v *ECDSAVerifier) KeyID() (string, error) {
	return GeneratePublicKeyID(v.pub, v.hash)
}

func (v *ECDSAVerifier) Verify(ctx context.Context, data []byte, sig []byte) error {
	digest, err := DigestBytes(data, v.hash)
	if err != nil {
		return err
	}

	verified := ecdsa.VerifyASN1(v.pub, digest, sig)
	if !verified {
		return ErrVerifyFailed{}
	}

	return nil
}

func (v *ECDSAVerifier) Public() crypto.PublicKey {
	return v.pub
}

func (v *ECDSAVerifier) Bytes() ([]byte, error) {
	return PublicPemBytes(v.pub)
}
