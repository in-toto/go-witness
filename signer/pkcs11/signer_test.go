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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/dsse"
	"github.com/stretchr/testify/require"
)

// fakeToken signs in software and returns r||s the way CKM_ECDSA does, so the
// Signer can be tested on every platform without a PKCS#11 module.
type fakeToken struct {
	priv   *ecdsa.PrivateKey
	closed bool
}

func (f *fakeToken) signDigest(digest []byte) ([]byte, error) {
	if f.closed {
		return nil, errors.New("signer is closed")
	}

	der, err := ecdsa.SignASN1(rand.Reader, f.priv, digest)
	if err != nil {
		return nil, err
	}

	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, err
	}

	size := rawSignatureLen(f.priv.Curve) / 2
	raw := make([]byte, 2*size)
	sig.R.FillBytes(raw[:size])
	sig.S.FillBytes(raw[size:])
	return raw, nil
}

func (f *fakeToken) close() error {
	f.closed = true
	return nil
}

func newFakeSigner(t *testing.T, curve elliptic.Curve) (*Signer, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	return &Signer{tok: &fakeToken{priv: priv}, pub: &priv.PublicKey}, priv
}

func TestEncodeSignature(t *testing.T) {
	for _, tc := range []struct{ name, raw, der string }{
		{"leading zero in r, high bit in s", "00018000", "30080201010203008000"},
		{"high bit in r, leading zeros in s", "ff000001", "3008020300ff00020101"},
		{"zero r", "0000007f", "300602010002017f"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := hex.DecodeString(tc.raw)
			require.NoError(t, err)
			got, err := encodeSignature(raw)
			require.NoError(t, err)
			require.Equal(t, tc.der, hex.EncodeToString(got))
		})
	}

	for _, raw := range [][]byte{nil, {}, {1}, {1, 2, 3}} {
		_, err := encodeSignature(raw)
		require.Error(t, err, "raw signature %x", raw)
	}
}

// DER is canonical, so re-encoding the fixed-width r||s of a signature made
// by crypto/ecdsa has to give back the same bytes.
func TestEncodeSignatureRoundTrip(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384()} {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		size := rawSignatureLen(curve) / 2
		for i := range 300 {
			digest, err := cryptoutil.DigestBytes([]byte{byte(i), byte(i >> 8)}, hash)
			require.NoError(t, err)
			der, err := ecdsa.SignASN1(rand.Reader, priv, digest)
			require.NoError(t, err)
			var sig struct{ R, S *big.Int }
			_, err = asn1.Unmarshal(der, &sig)
			require.NoError(t, err)

			raw := make([]byte, 2*size)
			sig.R.FillBytes(raw[:size])
			sig.S.FillBytes(raw[size:])
			got, err := encodeSignature(raw)
			require.NoError(t, err)
			require.Equal(t, der, got, curve.Params().Name)
		}
	}
}

func TestRawSignatureLen(t *testing.T) {
	require.Equal(t, 64, rawSignatureLen(elliptic.P256()))
	require.Equal(t, 96, rawSignatureLen(elliptic.P384()))
}

func TestParsePublicKey(t *testing.T) {
	// CKA_EC_PARAMS values as SoftHSM 2.6.1 returns them.
	params := map[string]string{"P-256": "06082a8648ce3d030107", "P-384": "06052b81040022"}
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(curve, rand.Reader)
			require.NoError(t, err)
			q, err := priv.PublicKey.Bytes()
			require.NoError(t, err)
			point, err := asn1.Marshal(q)
			require.NoError(t, err)
			ecParams, err := hex.DecodeString(params[curve.Params().Name])
			require.NoError(t, err)

			pub, err := parsePublicKey(ecParams, point)
			require.NoError(t, err)
			require.True(t, pub.Equal(&priv.PublicKey))

			_, err = parsePublicKey(ecParams, q)
			require.Error(t, err, "bare point without the OCTET STRING wrapper")
			_, err = parsePublicKey(append(ecParams, 0), point)
			require.Error(t, err, "byte after the OID")
			_, err = parsePublicKey(ecParams, append(point, 0))
			require.Error(t, err, "byte after the OCTET STRING")

			point[len(point)-1] ^= 1
			_, err = parsePublicKey(ecParams, point)
			require.Error(t, err, "point off the curve")
		})
	}

	p521, err := hex.DecodeString("06052b81040023")
	require.NoError(t, err)
	_, err = parsePublicKey(p521, nil)
	require.ErrorContains(t, err, "unsupported curve")

	_, err = parsePublicKey([]byte{0x05, 0x00}, nil)
	require.ErrorContains(t, err, "not a named curve OID")
}

func TestErrorText(t *testing.T) {
	require.EqualError(t, &ckError{"C_Login", 0xA0}, "C_Login: CKR_PIN_INCORRECT")
	require.EqualError(t, &ckError{"C_Sign", 0x80000001}, "C_Sign: CKR 0x80000001")
}

// The signature and the KeyID have to match what a verifier built from the
// public key PEM expects, because that is how policies and `witness verify -k`
// see the key.
func TestSignerMatchesPublicKeyVerifier(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			s, priv := newFakeSigner(t, curve)
			const msg = "attestation payload"
			sig, err := s.Sign(strings.NewReader(msg))
			require.NoError(t, err)

			pemBytes, err := cryptoutil.PublicPemBytes(&priv.PublicKey)
			require.NoError(t, err)
			fromPEM, err := cryptoutil.NewVerifierFromReader(bytes.NewReader(pemBytes))
			require.NoError(t, err)
			own, err := s.Verifier()
			require.NoError(t, err)

			wantID, err := fromPEM.KeyID()
			require.NoError(t, err)
			for _, v := range []cryptoutil.Verifier{fromPEM, own} {
				require.NoError(t, v.Verify(strings.NewReader(msg), sig))
				require.Error(t, v.Verify(strings.NewReader("another payload"), sig))
				id, err := v.KeyID()
				require.NoError(t, err)
				require.Equal(t, wantID, id)
			}

			id, err := s.KeyID()
			require.NoError(t, err)
			require.Equal(t, wantID, id)
		})
	}
}

func TestSignerDSSE(t *testing.T) {
	s, priv := newFakeSigner(t, elliptic.P256())
	env, err := dsse.Sign("application/vnd.in-toto+json", strings.NewReader(`{"a":1}`), dsse.SignWithSigners(s))
	require.NoError(t, err)

	verifier, err := cryptoutil.NewVerifier(&priv.PublicKey)
	require.NoError(t, err)
	_, err = env.Verify(dsse.VerifyWithVerifiers(verifier))
	require.NoError(t, err)
}

func TestSignerClose(t *testing.T) {
	s, _ := newFakeSigner(t, elliptic.P256())
	require.NoError(t, s.Close())
	_, err := s.Sign(strings.NewReader("after close"))
	require.ErrorContains(t, err, "pkcs11: signer is closed")
}
