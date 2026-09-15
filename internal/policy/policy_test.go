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

package policy

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"

	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/internal/test"
	"github.com/in-toto/go-witness/intoto"
	"github.com/in-toto/go-witness/timestamp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/in-toto/go-witness/cryptoutil"
)

func TestVerifyPolicySignature(t *testing.T) {
	// we dont care about the content of th envelope for this test
	rsaSigner, rsaVerifier, _, err := test.CreateTestKey()
	require.NoError(t, err)
	badRootCert, _, err := test.CreateRoot()
	require.NoError(t, err)
	rootCert, key, err := test.CreateRoot()
	require.NoError(t, err)
	leafCert, leafPriv, err := test.CreateLeaf(rootCert, key)
	require.NoError(t, err)
	x509Signer, err := cryptoutil.NewSigner(leafPriv, cryptoutil.SignWithCertificate(leafCert))
	require.NoError(t, err)

	timestampers := []timestamp.FakeTimestamper{
		{T: time.Now()},
		{T: time.Now().Add(12 * time.Hour)},
	}

	// Define the test cases.
	tests := []struct {
		name            string
		signer          cryptoutil.Signer
		verifier        cryptoutil.Verifier
		timestampers    []timestamp.FakeTimestamper
		Roots           []*x509.Certificate
		Intermediates   []*x509.Certificate
		certConstraints Option
		wantErr         bool
	}{
		{
			name:     "valid rsa signature",
			signer:   rsaSigner,
			verifier: rsaVerifier,
			// passing in timestampers to ensure that it is ignored
			timestampers: timestampers,
			wantErr:      false,
		},
		{
			name:    "invalid rsa signature",
			signer:  rsaSigner,
			Roots:   []*x509.Certificate{rootCert},
			wantErr: true,
		},
		{
			name:   "valid x509 signature",
			signer: x509Signer,
			Roots:  []*x509.Certificate{rootCert},
			// Identity constraints default to empty (fail closed), so trusting a CA requires an
			// explicit opt-in to accept any certificate under it. An explicit wildcard preserves the
			// "any cert under the trusted root" behavior.
			certConstraints: VerifyWithPolicyCertConstraints("*", []string{"*"}, []string{"*"}, []string{"*"}, []string{"*"}),
			wantErr:         false,
		},
		{
			name:   "valid x509 signature, trusted root but no identity constraints (fails closed)",
			signer: x509Signer,
			Roots:  []*x509.Certificate{rootCert},
			// No certConstraints: with the secure defaults a trusted CA alone must not accept an
			// arbitrary certificate that chains to it.
			wantErr: true,
		},
		{
			name:   "valid x509 signature w/ constraints",
			signer: x509Signer,
			// We're going to pass in to ensure that it is ignored
			Roots:           []*x509.Certificate{rootCert},
			certConstraints: VerifyWithPolicyCertConstraints(leafCert.Subject.CommonName, leafCert.DNSNames, []string{"*"}, []string{"*"}, []string{"*"}),
			timestampers:    timestampers,
			wantErr:         false,
		},
		{
			name:   "valid x509 signature w/ bad constraints",
			signer: x509Signer,
			// We're going to pass in to ensure that it is ignored
			Roots:           []*x509.Certificate{rootCert},
			certConstraints: VerifyWithPolicyCertConstraints("foo", []string{"bar"}, []string{"baz"}, []string{"qux"}, []string{"quux"}),
			wantErr:         true,
		},
		{
			name:   "unknown root",
			signer: x509Signer,
			// We're going to pass in to ensure that it is ignored
			Roots:   []*x509.Certificate{badRootCert},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		var ts []timestamp.Timestamper
		for _, t := range tt.timestampers {
			ts = append(ts, t)
		}

		env, err := dsse.Sign(intoto.PayloadType, bytes.NewReader([]byte("this is some test data")), dsse.SignWithTimestampers(ts...), dsse.SignWithSigners(tt.signer))
		require.NoError(t, err)

		var tv []timestamp.TimestampVerifier
		for _, t := range tt.timestampers {
			tv = append(tv, t)
		}

		o := []Option{}
		o = append(o, VerifyWithPolicyVerifiers([]cryptoutil.Verifier{tt.verifier}), VerifyWithPolicyCARoots(tt.Roots), VerifyWithPolicyTimestampAuthorities(tv))
		if tt.certConstraints != nil {
			o = append(o, tt.certConstraints)
		}

		vo := NewVerifyPolicySignatureOptions(o...)

		err = VerifyPolicySignature(context.TODO(), env, vo)
		assert.Equal(t, err != nil, tt.wantErr, "testName = %s, error = %v, wantErr = %v", tt.name, err, tt.wantErr)
	}
}

// createNamedLeaf mints a leaf certificate with a caller-chosen CommonName, signed by the supplied
// parent (root). It returns the leaf cert and its private key.
func createNamedLeaf(t *testing.T, parent *x509.Certificate, parentPriv interface{}, commonName string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	priv, pub, err := test.CreateRsaKey()
	require.NoError(t, err)
	template := &x509.Certificate{
		DNSNames: []string{"in-toto.io"},
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"In-toto"},
			CommonName:   commonName,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	cert, err := test.CreateCert(parentPriv, pub, template, parent)
	require.NoError(t, err)
	return cert, priv
}

// Trusting a CA via VerifyWithPolicyCARoots must not, on its own, accept every certificate that
// chains to it: an x509 policy signer is refused until the caller explicitly opts in to an identity
// constraint, so a certificate with an arbitrary identity must be rejected.
func TestVerifyPolicySignatureRequiresIdentityOptIn(t *testing.T) {
	root, rootPriv, err := test.CreateRoot()
	require.NoError(t, err)

	// A leaf with an arbitrary identity that merely chains to the trusted CA.
	priv, pub, err := test.CreateRsaKey()
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "someone@example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	cert, err := test.CreateCert(rootPriv, pub, tmpl, root)
	require.NoError(t, err)
	signer, err := cryptoutil.NewSigner(priv, cryptoutil.SignWithCertificate(cert))
	require.NoError(t, err)

	env, err := dsse.Sign(intoto.PayloadType, bytes.NewReader([]byte("policy payload")), dsse.SignWithSigners(signer))
	require.NoError(t, err)

	// Trust the CA but configure no identity constraint (rely on the defaults).
	vo := NewVerifyPolicySignatureOptions(VerifyWithPolicyCARoots([]*x509.Certificate{root}))

	require.Error(t, VerifyPolicySignature(context.TODO(), env, vo),
		"trusting a CA without any configured identity constraint must not accept an arbitrary certificate chaining to it")
}

// A signature that matches the policy's identity constraint but failed cryptographic verification
// must not confer trust. Here a second signature carries the trusted identity's certificate with
// forged bytes; only the untrusted identity's signature actually verifies, so the policy must fail.
func TestVerifyPolicySignatureRejectsFailedVerifier(t *testing.T) {
	rootCert, rootPriv, err := test.CreateRoot()
	require.NoError(t, err)

	// A low-value identity that chains to the trusted root and can produce a valid signature.
	otherCert, otherPriv := createNamedLeaf(t, rootCert, rootPriv, "other-ci@example.com")
	otherSigner, err := cryptoutil.NewSigner(otherPriv, cryptoutil.SignWithCertificate(otherCert))
	require.NoError(t, err)

	// The trusted identity's certificate (public only; its private key is not available here).
	trustedCert, _ := createNamedLeaf(t, rootCert, rootPriv, "release-signer@trusted.example")

	// Sign the policy with the low-value identity: a valid signature that meets the threshold.
	env, err := dsse.Sign(
		intoto.PayloadType,
		bytes.NewReader([]byte("policy payload")),
		dsse.SignWithSigners(otherSigner),
	)
	require.NoError(t, err)

	// Append a second signature carrying the trusted cert with forged bytes.
	trustedCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: trustedCert.Raw})
	env.Signatures = append(env.Signatures, dsse.Signature{
		Certificate: trustedCertPEM,
		Signature:   []byte("this-signature-was-never-produced-by-the-trusted-signer"),
	})

	// The policy trusts the release-signer identity (by CommonName) under the trusted root.
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCARoots([]*x509.Certificate{rootCert}),
		VerifyWithPolicyCertConstraints(
			"release-signer@trusted.example",
			[]string{"*"}, []string{"*"}, []string{"*"}, []string{"*"},
		),
	)

	require.Error(t, VerifyPolicySignature(context.TODO(), env, vo),
		"a certificate whose signature failed verification must not confer trust even when it matches the identity constraint")
}
