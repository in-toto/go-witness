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

package policy

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/commandrun"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/intoto"
	"github.com/in-toto/go-witness/signer"
	"github.com/in-toto/go-witness/source"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	// imported for TestPubKeyVerifiers -- so aws will be recognized as a supported provider
	_ "github.com/in-toto/go-witness/signer/kms/aws"
)

func init() {
	attestation.RegisterAttestation("dummy-prods", "dummy-prods", attestation.PostProductRunType, func() attestation.Attestor {
		return &DummyProducer{}
	})
	attestation.RegisterAttestation("dummy-mats", "dummy-mats", attestation.PreMaterialRunType, func() attestation.Attestor {
		return &DummyMaterialer{}
	})
}

func createTestKey() (cryptoutil.Signer, cryptoutil.Verifier, []byte, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}

	signer := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
	verifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)
	keyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, nil, err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: keyBytes})
	if err != nil {
		return nil, nil, nil, err
	}

	return signer, verifier, pemBytes, nil
}

func TestVerify(t *testing.T) {
	_, verifier, pubKeyPem, err := createTestKey()
	require.NoError(t, err)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)
	_, verifier2, pubKeyPem2, err := createTestKey()
	require.NoError(t, err)
	keyID2, err := verifier2.KeyID()
	require.NoError(t, err)
	commandPolicy := []byte(`package test
deny[msg] {
	input.cmd != ["go", "build", "./"]
	msg := "unexpected cmd"
}`)
	exitPolicy := []byte(`package commandrun.exitcode
deny[msg] {
	input.exitcode != 0
	msg := "exitcode not 0"
}`)

	policy := Policy{
		Expires: metav1.NewTime(time.Now().Add(1 * time.Hour)),
		PublicKeys: map[string]PublicKey{
			keyID: {
				KeyID: keyID,
				Key:   pubKeyPem,
			},
			keyID2: {
				KeyID: keyID2,
				Key:   pubKeyPem2,
			},
		},
		Steps: map[string]Step{
			"step1": {
				Name: "step1",
				Functionaries: []Functionary{
					{
						Type:        "PublicKey",
						PublicKeyID: keyID,
					},
				},
				Attestations: []Attestation{
					{
						Type: commandrun.Type,
						RegoPolicies: []RegoPolicy{
							{
								Module: commandPolicy,
								Name:   "expected command",
							},
							{
								Name:   "exited successfully",
								Module: exitPolicy,
							},
						},
					},
				},
			},
		},
	}

	commandRun := commandrun.New()
	commandRun.Cmd = []string{"go", "build", "./"}
	commandRun.ExitCode = 0

	step1Collection := attestation.NewCollection("step1", []attestation.CompletedAttestor{
		{
			Attestor:  commandRun,
			StartTime: time.Now().Add(-1 * time.Minute),
			EndTime:   time.Now(),
			Error:     nil,
		},
	})

	step1CollectionJson, err := json.Marshal(&step1Collection)
	require.NoError(t, err)
	intotoStatement, err := intoto.NewStatement(attestation.CollectionType, step1CollectionJson, map[string]cryptoutil.DigestSet{"dummy": {cryptoutil.DigestValue{Hash: crypto.SHA256}: "dummy"}})
	require.NoError(t, err)

	pass, _, err := policy.Verify(
		context.Background(),
		WithSubjectDigests([]string{"dummy"}),
		WithVerifiedSource(
			newDummyVerifiedSourcer([]source.CollectionVerificationResult{
				{
					Verifiers: []cryptoutil.Verifier{verifier},
					CollectionEnvelope: source.CollectionEnvelope{
						Statement:  intotoStatement,
						Collection: step1Collection,
						Reference:  "1",
					},
				},
			}),
		),
	)
	assert.NoError(t, err)
	assert.Equal(t, true, pass)

	pass, results, err := policy.Verify(
		context.Background(),
		WithSubjectDigests([]string{"dummy"}),
		WithVerifiedSource(
			newDummyVerifiedSourcer([]source.CollectionVerificationResult{
				{
					Verifiers: []cryptoutil.Verifier{},
					CollectionEnvelope: source.CollectionEnvelope{
						Statement:  intotoStatement,
						Collection: step1Collection,
						Reference:  "1",
					},
				},
			}),
		),
	)
	assert.NoError(t, err)
	assert.Equal(t, false, pass)

	for _, result := range results {
		if result.Analyze() == false {
			return
		}
	}

	assert.Fail(t, "expected a failure")
}

func TestArtifacts(t *testing.T) {
	_, verifier, pubKeyPem, err := createTestKey()
	require.NoError(t, err)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)

	policy := Policy{
		Expires: metav1.NewTime(time.Now().Add(1 * time.Hour)),
		PublicKeys: map[string]PublicKey{
			keyID: {
				KeyID: keyID,
				Key:   pubKeyPem,
			},
		},
		Steps: map[string]Step{
			"step1": {
				Name: "step1",
				Functionaries: []Functionary{
					{
						Type:        "PublicKey",
						PublicKeyID: keyID,
					},
				},
				Attestations: []Attestation{
					{
						Type: "dummy-prods",
					},
				},
			},
			"step2": {
				Name:          "step2",
				ArtifactsFrom: []string{"step1"},
				Functionaries: []Functionary{
					{
						Type:        "PublicKey",
						PublicKeyID: keyID,
					},
				},
				Attestations: []Attestation{
					{
						Type: "dummy-mats",
					},
				},
			},
		},
	}

	dummySha := "a1073968266a4ed65472a80ebcfd31f1955cfdf8f23d439b1df84d78ce05f7a9"
	path := "testfile"
	mats := map[string]cryptoutil.DigestSet{path: {cryptoutil.DigestValue{Hash: crypto.SHA256}: dummySha}}
	prods := map[string]attestation.Product{path: {Digest: cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256}: dummySha}, MimeType: "application/text"}}

	step1Collection := attestation.NewCollection("step1", []attestation.CompletedAttestor{
		{
			Attestor:  DummyProducer{prods},
			StartTime: time.Now().Add(-1 * time.Minute),
			EndTime:   time.Now(),
			Error:     nil,
		},
	})

	step2Collection := attestation.NewCollection("step2", []attestation.CompletedAttestor{
		{
			Attestor:  DummyMaterialer{mats},
			StartTime: time.Now().Add(-1 * time.Minute),
			EndTime:   time.Now(),
			Error:     nil,
		},
	})

	step1CollectionJson, err := json.Marshal(step1Collection)
	require.NoError(t, err)
	step2CollectionJson, err := json.Marshal(step2Collection)
	require.NoError(t, err)
	intotoStatement1, err := intoto.NewStatement(attestation.CollectionType, step1CollectionJson, map[string]cryptoutil.DigestSet{})
	require.NoError(t, err)
	intotoStatement2, err := intoto.NewStatement(attestation.CollectionType, step2CollectionJson, map[string]cryptoutil.DigestSet{})
	require.NoError(t, err)
	pass, _, err := policy.Verify(
		context.Background(),
		WithSubjectDigests([]string{dummySha}),
		WithVerifiedSource(newDummyVerifiedSourcer([]source.CollectionVerificationResult{
			{
				Verifiers: []cryptoutil.Verifier{verifier},
				CollectionEnvelope: source.CollectionEnvelope{
					Statement:  intotoStatement1,
					Collection: step1Collection,
					Reference:  "1",
				},
			},
			{
				Verifiers: []cryptoutil.Verifier{verifier},
				CollectionEnvelope: source.CollectionEnvelope{
					Statement:  intotoStatement2,
					Collection: step2Collection,
					Reference:  "2",
				},
			},
		})),
	)
	assert.NoError(t, err)
	assert.Equal(t, true, pass)

	mats[path][cryptoutil.DigestValue{Hash: crypto.SHA256}] = "badhash"

	step2Collection = attestation.NewCollection("step2", []attestation.CompletedAttestor{
		{
			Attestor:  DummyMaterialer{mats},
			StartTime: time.Now().Add(-1 * time.Minute),
			EndTime:   time.Now(),
			Error:     nil,
		},
	})

	step2CollectionJson, err = json.Marshal(step2Collection)
	require.NoError(t, err)
	intotoStatement2, err = intoto.NewStatement(attestation.CollectionType, step2CollectionJson, map[string]cryptoutil.DigestSet{})
	require.NoError(t, err)
	pass, results, err := policy.Verify(
		context.Background(),
		WithSubjectDigests([]string{dummySha}),
		WithVerifiedSource(newDummyVerifiedSourcer([]source.CollectionVerificationResult{
			{
				Verifiers: []cryptoutil.Verifier{verifier},
				CollectionEnvelope: source.CollectionEnvelope{
					Statement:  intotoStatement1,
					Collection: step1Collection,
					Reference:  "1",
				},
			},
			{
				Verifiers: []cryptoutil.Verifier{verifier},
				CollectionEnvelope: source.CollectionEnvelope{
					Statement:  intotoStatement2,
					Collection: step2Collection,
					Reference:  "2",
				},
			},
		})),
	)

	assert.Equal(t, pass, false)
	assert.NoError(t, err)

	for _, result := range results {
		if result.Analyze() == false {
			assert.Contains(t, result.Error(), "failed to verify artifacts for step step2")
			assert.Contains(t, result.Error(), "failed to verify artifacts: [mismatched digests for testfile]")
			return
		}
	}

	assert.Fail(t, "expected a failure")
}

type DummyMaterialer struct {
	M map[string]cryptoutil.DigestSet
}

func (DummyMaterialer) Name() string {
	return "dummy-mats"
}

func (DummyMaterialer) Type() string {
	return "dummy-mats"
}

func (DummyMaterialer) RunType() attestation.RunType {
	return attestation.PreMaterialRunType
}

func (DummyMaterialer) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(DummyMaterialer{})
}

func (DummyMaterialer) Attest(*attestation.AttestationContext) error {
	return nil
}

func (m DummyMaterialer) Materials() map[string]cryptoutil.DigestSet {
	return m.M
}

type DummyProducer struct {
	P map[string]attestation.Product
}

func (DummyProducer) Name() string {
	return "dummy-prods"
}

func (DummyProducer) Type() string {
	return "dummy-prods"
}

func (DummyProducer) RunType() attestation.RunType {
	return attestation.PostProductRunType
}

func (DummyProducer) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(DummyProducer{})
}

func (DummyProducer) Attest(*attestation.AttestationContext) error {
	return nil
}

func (m DummyProducer) Products() map[string]attestation.Product {
	return m.P
}

type dummyVerifiedSourcer struct {
	verifiedCollections []source.CollectionVerificationResult
}

func newDummyVerifiedSourcer(verifiedCollections []source.CollectionVerificationResult) *dummyVerifiedSourcer {
	return &dummyVerifiedSourcer{verifiedCollections}
}

func (s *dummyVerifiedSourcer) Search(ctx context.Context, collectionName string, subjectDigests, attestations []string) ([]source.CollectionVerificationResult, error) {
	return s.verifiedCollections, nil
}

func TestPubKeyVerifiers(t *testing.T) {
	const numTestKeys = 5
	type testVerifier struct {
		keyID    string
		verifier cryptoutil.Verifier
		keyBytes []byte
	}

	testVerifiers := make([]testVerifier, 0, numTestKeys)
	for i := 0; i < numTestKeys; i++ {
		_, verifier, keyBytes, err := createTestKey()
		require.NoError(t, err)
		keyID, err := verifier.KeyID()
		require.NoError(t, err)
		testVerifiers = append(testVerifiers, testVerifier{
			keyID,
			verifier,
			keyBytes,
		})
	}

	mismatchedKeyIDVerifiers := make([]testVerifier, numTestKeys)
	copy(mismatchedKeyIDVerifiers, testVerifiers)
	mismatchedKeyIDVerifiers[numTestKeys-2].keyID = mismatchedKeyIDVerifiers[numTestKeys-2].keyID + "uhoh"

	// Create a test key for KMS offline verification tests
	_, kmsVerifier, kmsKeyBytes, err := createTestKey()
	require.NoError(t, err)

	testCases := []struct {
		name          string
		testVerifiers []testVerifier
		expectedErr   error
		expectedLen   int
	}{
		{
			name:          "all pubkeys",
			testVerifiers: testVerifiers,
			expectedErr:   nil,
			expectedLen:   len(testVerifiers),
		},
		{
			name:          "key id mismatch",
			testVerifiers: mismatchedKeyIDVerifiers,
			expectedErr:   ErrKeyIDMismatch{},
			expectedLen:   len(mismatchedKeyIDVerifiers),
		},
		{
			// Test KMS key ID with embedded key (offline/air-gap verification)
			// The embedded key should be used for verification instead of contacting KMS
			name: "kms keyid with embedded key (offline verification)",
			testVerifiers: append(testVerifiers, testVerifier{
				keyID:    "awskms:///1234abcd-12ab-34cd-56ef-1234567890ab",
				verifier: kmsVerifier,
				keyBytes: kmsKeyBytes,
			}),
			expectedErr: nil,
			expectedLen: len(testVerifiers) + 1,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			p := Policy{PublicKeys: map[string]PublicKey{}}
			for _, v := range testCase.testVerifiers {
				p.PublicKeys[v.keyID] = PublicKey{
					KeyID: v.keyID,
					Key:   v.keyBytes,
				}
			}

			verifiers, err := p.PublicKeyVerifiers(map[string][]func(signer.SignerProvider) (signer.SignerProvider, error){})
			if testCase.expectedErr == nil {
				assert.NoError(t, err)
				assert.Len(t, verifiers, testCase.expectedLen)
			} else {
				assert.Error(t, err)
				assert.IsType(t, testCase.expectedErr, err)
			}
		})
	}
}

// TestKMSOfflineVerification tests the offline/air-gap verification feature
// where a KMS-style key ID is used with an embedded public key.
// This enables verification without contacting the KMS service.
func TestKMSOfflineVerification(t *testing.T) {
	// Create a test key that will be embedded in the policy
	testSigner, testVerifier, keyBytes, err := createTestKey()
	require.NoError(t, err)

	signerKeyID, err := testSigner.KeyID()
	require.NoError(t, err)

	verifierKeyID, err := testVerifier.KeyID()
	require.NoError(t, err)

	// Sanity check: signer and verifier should have the same key ID
	require.Equal(t, signerKeyID, verifierKeyID)

	// Test cases for KMS offline verification
	// Note: Only AWS KMS is imported in this test file, so only awskms:// prefixes are recognized as KMS providers
	testCases := []struct {
		name           string
		kmsKeyID       string
		embeddedKey    []byte
		expectError    bool
		errorContains  string
		verifyKeyID    string // The key ID we expect in the resulting verifiers map
	}{
		{
			name:        "AWS KMS key ID with embedded key",
			kmsKeyID:    "awskms:///1234abcd-12ab-34cd-56ef-1234567890ab",
			embeddedKey: keyBytes,
			expectError: false,
			verifyKeyID: "awskms:///1234abcd-12ab-34cd-56ef-1234567890ab",
		},
		{
			name:        "AWS KMS ARN with embedded key",
			kmsKeyID:    "awskms:///arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab",
			embeddedKey: keyBytes,
			expectError: false,
			verifyKeyID: "awskms:///arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		},
		{
			name:          "Invalid embedded key should fail",
			kmsKeyID:      "awskms:///1234abcd-12ab-34cd-56ef-1234567890ab",
			embeddedKey:   []byte("not a valid key"),
			expectError:   true,
			errorContains: "failed to create verifier from embedded key",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := Policy{
				PublicKeys: map[string]PublicKey{
					tc.kmsKeyID: {
						KeyID: tc.kmsKeyID,
						Key:   tc.embeddedKey,
					},
				},
			}

			verifiers, err := p.PublicKeyVerifiers(map[string][]func(signer.SignerProvider) (signer.SignerProvider, error){})

			if tc.expectError {
				require.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
				return // Skip the rest of the test for error cases
			}

			require.NoError(t, err)
			require.Len(t, verifiers, 1)

			// Verify the key is stored with the KMS key ID (not the computed hash)
			v, ok := verifiers[tc.verifyKeyID]
			require.True(t, ok, "verifier should be stored with KMS key ID: %s", tc.verifyKeyID)
			require.NotNil(t, v)

			// Verify the verifier can be used (sign and verify a message)
			message := []byte("test message for verification")
			sig, err := testSigner.Sign(bytes.NewReader(message))
			require.NoError(t, err)

			err = v.Verify(bytes.NewReader(message), sig)
			assert.NoError(t, err, "embedded key verifier should be able to verify signatures")
		})
	}
}

// TestKMSOfflineVerificationWithFunctionaries tests that the offline KMS verification
// works correctly with the functionary matching logic in policy verification.
func TestKMSOfflineVerificationWithFunctionaries(t *testing.T) {
	// Create a test key
	testSigner, testVerifier, keyBytes, err := createTestKey()
	require.NoError(t, err)

	kmsKeyID := "awskms:///test-key-12345678-1234-1234-1234-123456789012"

	// Create a policy with a KMS key ID and embedded key
	p := Policy{
		PublicKeys: map[string]PublicKey{
			kmsKeyID: {
				KeyID: kmsKeyID,
				Key:   keyBytes,
			},
		},
	}

	// Get verifiers from the policy
	verifiers, err := p.PublicKeyVerifiers(map[string][]func(signer.SignerProvider) (signer.SignerProvider, error){})
	require.NoError(t, err)
	require.Len(t, verifiers, 1)

	// The verifier should be accessible by the KMS key ID
	v, ok := verifiers[kmsKeyID]
	require.True(t, ok, "verifier should be stored with KMS key ID")

	// Verify that signatures made with the original signer can be verified
	message := []byte("test message")
	sig, err := testSigner.Sign(bytes.NewReader(message))
	require.NoError(t, err)

	err = v.Verify(bytes.NewReader(message), sig)
	assert.NoError(t, err, "should verify signature using embedded key")

	// Also verify that the test verifier produces the same result
	err = testVerifier.Verify(bytes.NewReader(message), sig)
	assert.NoError(t, err, "original verifier should also verify the signature")
}

func TestCheckFunctionaries(t *testing.T) {
	signers := []cryptoutil.Signer{}
	verifiers := []cryptoutil.Verifier{}
	for i := 0; i < 7; i++ {
		signer, verifier, _, err := createTestKey()
		if err != nil {
			log.Fatal(err)
		}

		signers = append(signers, signer)
		verifiers = append(verifiers, verifier)
	}

	keyIDs := make([]string, 0, len(signers))
	for _, s := range signers {
		keyID, err := s.KeyID()
		if err != nil {
			log.Fatal(err)
		}

		keyIDs = append(keyIDs, keyID)
	}

	testCases := []struct {
		name         string
		step         Step
		statements   []source.CollectionVerificationResult
		trustBundles map[string]TrustBundle
		// expectedResults is a list of results with each entry containing only the fields that we wish to check (errors, warnings, valid functionaries)
		// this is so we can compare the results without needing to copy the unnecessary fields in the testcase definitions below
		expectedResults []source.CollectionVerificationResult
	}{
		{
			name: "simple 1 functionary pass",
			step: Step{
				Name: "step1",
				Functionaries: []Functionary{
					{Type: "PublicKey", PublicKeyID: keyIDs[0]},
				},
				Attestations: []Attestation{
					{Type: "dummy-prods"},
					{Type: "dummy-mats"},
				},
			},
			statements: []source.CollectionVerificationResult{
				{
					Verifiers: []cryptoutil.Verifier{verifiers[0]},
					CollectionEnvelope: source.CollectionEnvelope{
						Statement: intoto.Statement{PredicateType: attestation.CollectionType},
					},
				},
			},
			expectedResults: []source.CollectionVerificationResult{
				{
					ValidFunctionaries: []cryptoutil.Verifier{
						verifiers[0],
					},
				},
			},
		},
		{
			name: "invalid functionary",
			step: Step{
				Name: "step1",
				Functionaries: []Functionary{
					{Type: "PublicKey", PublicKeyID: keyIDs[0]},
				},
				Attestations: []Attestation{
					{Type: "dummy-prods"},
					{Type: "dummy-mats"},
				},
			},
			statements: []source.CollectionVerificationResult{
				{
					Verifiers: []cryptoutil.Verifier{verifiers[1]},
					CollectionEnvelope: source.CollectionEnvelope{
						Statement: intoto.Statement{PredicateType: attestation.CollectionType},
					},
				},
			},
			expectedResults: []source.CollectionVerificationResult{
				{
					Warnings: []string{fmt.Sprintf("failed to validate functionary of KeyID %s in step step1: verifier with ID %s is not a public key verifier or a x509 verifier", keyIDs[0], keyIDs[1])},
				},
			},
		},
	}

	for _, testCase := range testCases {
		fmt.Println("running test case: ", testCase.name)
		result := testCase.step.checkFunctionaries(testCase.statements, testCase.trustBundles)
		resultCheckFields := []source.CollectionVerificationResult{}
		for _, r := range result.Passed {
			o := source.CollectionVerificationResult{
				Errors:             r.Errors,
				Warnings:           r.Warnings,
				ValidFunctionaries: r.ValidFunctionaries,
			}
			resultCheckFields = append(resultCheckFields, o)
		}

		for _, r := range result.Rejected {
			o := source.CollectionVerificationResult{
				Errors:             r.Collection.Errors,
				Warnings:           r.Collection.Warnings,
				ValidFunctionaries: r.Collection.ValidFunctionaries,
			}
			resultCheckFields = append(resultCheckFields, o)
		}

		assert.Equal(t, testCase.expectedResults, resultCheckFields)
	}
}
