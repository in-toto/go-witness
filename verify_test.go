// Copyright 2024 The Witness Contributors
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

package witness

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/internal/test"
	"github.com/in-toto/go-witness/intoto"
	"github.com/in-toto/go-witness/timestamp"

	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/source"
)

func TestVerifyPolicySignature(t *testing.T) {
	// we dont care about the content of th envelope for this test
	rsaSigner, rsaVerifier, _, err := test.CreateTestKey()
	if err != nil {
		t.Fatal(err)
	}

	badRootCert, _, err := test.CreateRoot()
	if err != nil {
		t.Fatal(err)
	}

	rootCert, key, err := test.CreateRoot()
	if err != nil {
		t.Fatal(err)
	}

	leafCert, leafPriv, err := test.CreateLeaf(rootCert, key)
	if err != nil {
		t.Fatal(err)
	}

	x509Signer, err := cryptoutil.NewSigner(leafPriv, cryptoutil.SignWithCertificate(leafCert))
	if err != nil {
		t.Fatal(err)
	}

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
		certConstraints VerifyOption
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
			// We're going to pass in to ensure that it is ignored
			Roots:   []*x509.Certificate{rootCert},
			wantErr: false,
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
		if err != nil {
			t.Fatal(err)
		}

		var tv []timestamp.TimestampVerifier
		for _, t := range tt.timestampers {
			tv = append(tv, t)
		}

		vo := verifyOptions{
			policyEnvelope:             env,
			policyVerifiers:            []cryptoutil.Verifier{tt.verifier},
			policyCARoots:              tt.Roots,
			policyTimestampAuthorities: tv,
			policyCommonName:           "*",
			policyDNSNames:             []string{"*"},
			policyOrganizations:        []string{"*"},
			policyURIs:                 []string{"*"},
			policyEmails:               []string{"*"},
		}

		if tt.certConstraints != nil {
			tt.certConstraints(&vo)
		}

		err = verifyPolicySignature(context.TODO(), vo)
		if err != nil && !tt.wantErr {
			t.Errorf("testName = %s, error = %v, wantErr %v", tt.name, err, tt.wantErr)
		} else {
			fmt.Printf("test %s passed\n", tt.name)
		}

	}
}

func TestPolicyVerification(t *testing.T) {
	testdataDir := "hack/testdata"
	dirs, err := os.ReadDir(testdataDir)
	if err != nil {
		t.Fatalf("Failed to read testdata directory: %v", err)
	}
	for _, dir := range dirs {
		dirPath := filepath.Join(testdataDir, dir.Name())
		policyPublicKey, err := os.ReadFile(filepath.Join(dirPath, "policy.pub"))
		if err != nil {
			t.Fatalf("Failed to read policy public key: %v", err)
		}

		policySigned, err := os.ReadFile(filepath.Join(dirPath, "policysigned.json"))
		if err != nil {
			t.Fatalf("Failed to read policy signed: %v", err)
		}

		t.Run(dir.Name(), func(t *testing.T) {
			attestations := [][]byte{}

			// attestations are the remaining files in the directory
			files, err := os.ReadDir(dirPath)
			if err != nil {
				t.Fatalf("Failed to read directory: %v", err)
			}
			for _, file := range files {
				if !file.IsDir() && file.Name() != "policy.pub" && file.Name() != "policysigned.json" && file.Name() != "policy.json" {
					attestationPath := filepath.Join(dirPath, file.Name())
					attestationBytes, err := os.ReadFile(attestationPath)
					if err != nil {
						t.Fatalf("Failed to read attestation: %v", err)
					}

					attestations = append(attestations, attestationBytes)
				}
			}

			VerifyPolicyWithAttestations(t, policyPublicKey, policySigned, attestations)
		})

	}
}

// VerifyPolicyWithAttestations is a test helper that verifies a signed policy and its attestations.
func VerifyPolicyWithAttestations(t *testing.T, policyPublicKey, policySigned []byte, attestations [][]byte) {
	ctx := context.Background()

	// create a reader for the public key
	policyPublicKeyReader := bytes.NewReader(policyPublicKey)

	// create verifier for the public key
	k, err := cryptoutil.NewVerifierFromReader(policyPublicKeyReader)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	// parse policy into dsse envelope
	policyEnvelope, err := VerifySignature(bytes.NewReader(policySigned), k)
	if err != nil {
		t.Fatalf("Failed to verify policy signature: %v", err)
	}

	memSource := source.NewMemorySource()
	for i, path := range attestations {
		reference := fmt.Sprintf("attestation-%d", i)

		if err := memSource.LoadBytes(reference, path); err != nil {
			t.Fatalf("Failed to load attestation %s: %v", path, err)
		}
	}

	// Verify the policy with attestations
	ok, _, err := Verify(ctx, policyEnvelope, []cryptoutil.Verifier{k}, VerifyWithCollectionSource(memSource))
	if err != nil {
		t.Fatalf("Failed to verify policy: %v", err)
	}

	if !ok {
		t.Fatalf("Policy verification failed")
	}
}
