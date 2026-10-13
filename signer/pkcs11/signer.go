// Copyright 2026 The Witness Contributors
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

package pkcs11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/in-toto/go-witness/cryptoutil"
)

// The digest is always SHA-256, for P-384 keys too. go-witness builds the
// verifiers for policy public keys and for `witness verify -k` with SHA-256,
// and the KeyID of those verifiers is the SHA-256 of the public key PEM.
const hash = crypto.SHA256

// token is the part of the signer that talks to the PKCS#11 module.
type token interface {
	// signDigest returns the signature as CKM_ECDSA produces it: r||s, each
	// half as long as the order of the curve.
	signDigest(digest []byte) ([]byte, error)
	close() error
}

// Signer is a cryptoutil.Signer for one private key on a token. It is safe
// for concurrent use.
type Signer struct {
	tok token
	pub *ecdsa.PublicKey
}

func (s *Signer) KeyID() (string, error) {
	return cryptoutil.GeneratePublicKeyID(s.pub, hash)
}

// Sign hashes r and returns an ASN.1 DER encoded ECDSA signature of the digest.
func (s *Signer) Sign(r io.Reader) ([]byte, error) {
	digest, err := cryptoutil.Digest(r, hash)
	if err != nil {
		return nil, err
	}

	raw, err := s.tok.signDigest(digest)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: %w", err)
	}

	return encodeSignature(raw)
}

func (s *Signer) Verifier() (cryptoutil.Verifier, error) {
	return cryptoutil.NewECDSAVerifier(s.pub, hash), nil
}

// Close ends the session with the token. cryptoutil.Signer has no Close, so a
// caller that outlives its signer has to assert for io.Closer.
func (s *Signer) Close() error {
	if err := s.tok.close(); err != nil {
		return fmt.Errorf("pkcs11: %w", err)
	}

	return nil
}

var (
	oidP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
)

// parsePublicKey builds the key from CKA_EC_PARAMS (DER OID of a named curve)
// and CKA_EC_POINT (DER OCTET STRING wrapped around the uncompressed point).
func parsePublicKey(params, point []byte) (*ecdsa.PublicKey, error) {
	var oid asn1.ObjectIdentifier
	if rest, err := asn1.Unmarshal(params, &oid); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("CKA_EC_PARAMS is not a named curve OID: %x", params)
	}

	var curve elliptic.Curve
	switch {
	case oid.Equal(oidP256):
		curve = elliptic.P256()
	case oid.Equal(oidP384):
		curve = elliptic.P384()
	default:
		return nil, fmt.Errorf("unsupported curve %v", oid)
	}

	var q []byte
	if rest, err := asn1.Unmarshal(point, &q); err != nil || len(rest) != 0 {
		return nil, errors.New("CKA_EC_POINT is not a DER OCTET STRING")
	}

	pub, err := ecdsa.ParseUncompressedPublicKey(curve, q)
	if err != nil {
		return nil, fmt.Errorf("CKA_EC_POINT: %w", err)
	}

	return pub, nil
}

// rawSignatureLen is the length of the r||s value CKM_ECDSA returns for curve.
func rawSignatureLen(curve elliptic.Curve) int {
	return 2 * ((curve.Params().N.BitLen() + 7) / 8)
}

// encodeSignature turns the fixed-width r||s of CKM_ECDSA into the ASN.1 DER
// SEQUENCE{r, s} that cryptoutil.ECDSAVerifier takes.
func encodeSignature(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw)%2 != 0 {
		return nil, fmt.Errorf("ECDSA signature has odd or zero length %d", len(raw))
	}

	half := len(raw) / 2
	return asn1.Marshal(struct{ R, S *big.Int }{
		new(big.Int).SetBytes(raw[:half]),
		new(big.Int).SetBytes(raw[half:]),
	})
}
