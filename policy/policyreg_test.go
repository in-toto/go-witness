package policy_test

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
	"testing"
	"time"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	// go-witness imports in your module:
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/intoto"
	"github.com/in-toto/go-witness/policy"
	"github.com/in-toto/go-witness/source"

	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/require"
)

// -------------------------------------------------------------
// 1) Minimal DummyProducer so we can embed a "dummy-prods" attestation
// -------------------------------------------------------------
type DummyProducer struct{}

func (DummyProducer) Name() string {
	return "dummy-prods"
}

func (DummyProducer) Type() string {
	return "dummy-prods"
}

// We mark it as a collection run type so it fits the policy's
// step.checkFunctionaries( ) check requiring `attestation.CollectionType`.
func (DummyProducer) RunType() attestation.RunType {
	return attestation.CollectionType
}

func (DummyProducer) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(DummyProducer{})
}

func (DummyProducer) Attest(*attestation.AttestationContext) error {
	return nil
}

// If you need to produce “products”, you can return a map here. We'll keep it empty.
func (DummyProducer) Products() map[string]attestation.Product {
	return map[string]attestation.Product{}
}

// -------------------------------------------------------------
// 2) Helper to generate ephemeral RSA key + DSSE signing
// -------------------------------------------------------------
func createTestKey() (cryptoutil.Signer, cryptoutil.Verifier, []byte, string, error) {
	// Generate RSA key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, "", err
	}
	signer := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
	verifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)

	// Convert public key to PEM
	pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, nil, "", err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	keyID, err := verifier.KeyID()
	if err != nil {
		return nil, nil, nil, "", err
	}

	return signer, verifier, pemBytes, keyID, nil
}

// signStatement marshals an in-toto Statement + signs it using dsse.Sign
func signStatement(
	signer cryptoutil.Signer,
	statement intoto.Statement,
) (dsse.Envelope, error) {
	payloadBytes, _ := json.Marshal(statement)

	// dsse.Sign requires bodyType + a reader for the payload
	env, err := dsse.Sign(
		"application/vnd.in-toto+json",
		bytesReader(payloadBytes),
		dsse.SignWithSigners(signer),
	)
	if err != nil {
		return dsse.Envelope{}, err
	}
	return env, nil
}

// A small helper since we don't do "strings.NewReader" for []byte
func bytesReader(b []byte) *bytes.Reader {
	return bytes.NewReader(b)
}

// -------------------------------------------------------------
// 3) Build an attestation.Collection referencing "dummy-prods"
// -------------------------------------------------------------
func newDummyProdsCollection(stepName string) attestation.Collection {
	// One attestor => "dummy-prods"
	dummyRun := attestation.CompletedAttestor{
		Attestor:  DummyProducer{},
		StartTime: time.Now().Add(-1 * time.Minute),
		EndTime:   time.Now(),
		Error:     nil, // or an error if you want
	}

	return attestation.NewCollection(stepName, []attestation.CompletedAttestor{dummyRun})
}

// -------------------------------------------------------------
// 4) The actual test verifying multi-depth search
// -------------------------------------------------------------
func TestMemorySourceDepthRegression(t *testing.T) {
	ctx := context.Background()

	// A) Generate ephemeral RSA key so we can sign envelopes
	signer, verifier, pubKeyPEM, keyID, err := createTestKey()
	require.NoError(t, err)

	// B) Build "build" step => references artifactA + artifactB
	buildColl := newDummyProdsCollection("build")
	buildCollJSON, _ := json.Marshal(buildColl)

	stmtBuild := intoto.Statement{
		Type: intoto.StatementType,
		// Must match code in checkFunctionaries => "predicate type is not a collection predicate type"
		PredicateType: attestation.CollectionType,
		Subject: []intoto.Subject{
			{
				Name:   "artifactA",
				Digest: map[string]string{"sha256": fmt.Sprintf("%x", []byte("artifactA"))},
			},
			{
				Name:   "artifactB",
				Digest: map[string]string{"sha256": fmt.Sprintf("%x", []byte("artifactB"))},
			},
		},
		// The attestation.Collection is the statement's raw "predicate"
		Predicate: buildCollJSON,
	}

	envBuild, err := signStatement(signer, stmtBuild)
	require.NoError(t, err)

	// C) Build "test" step => references only artifactB
	testColl := newDummyProdsCollection("test")
	testCollJSON, _ := json.Marshal(testColl)

	stmtTest := intoto.Statement{
		Type:          intoto.StatementType,
		PredicateType: attestation.CollectionType,
		Subject: []intoto.Subject{
			{
				Name:   "artifactB",
				Digest: map[string]string{"sha256": fmt.Sprintf("%x", []byte("artifactB"))},
			},
		},
		Predicate: testCollJSON,
	}

	envTest, err := signStatement(signer, stmtTest)
	require.NoError(t, err)

	// D) Load them into a MemorySource
	mem := source.NewMemorySource()

	err = mem.LoadEnvelope("reference-build", envBuild)
	require.NoError(t, err, "failed to load 'build' envelope")
	err = mem.LoadEnvelope("reference-test", envTest)
	require.NoError(t, err, "failed to load 'test' envelope")

	// E) Policy referencing ephemeral public key + 2 steps
	pol := policy.Policy{
		Expires: v1.NewTime(time.Now().Add(3 * 365 * 24 * time.Hour)), // ~3 years
		PublicKeys: map[string]policy.PublicKey{
			keyID: {
				KeyID: keyID,
				Key:   pubKeyPEM,
			},
		},
		Steps: map[string]policy.Step{
			"build": {
				Name: "build",
				Functionaries: []policy.Functionary{
					{
						Type:        "PublicKey",
						PublicKeyID: keyID, // must match ephemeral key
					},
				},
				// The code will look inside "collection.Collection.Attestations"
				// for "dummy-prods"
				Attestations: []policy.Attestation{
					{Type: "dummy-prods"},
				},
			},
			"test": {
				Name: "test",
				Functionaries: []policy.Functionary{
					{
						Type:        "PublicKey",
						PublicKeyID: keyID,
					},
				},
				Attestations: []policy.Attestation{
					{Type: "dummy-prods"},
				},
			},
		},
	}

	// F) Subject digests => artifactA at depth=0
	subjectDigests := []string{
		fmt.Sprintf("%x", []byte("artifactA")),
	}

	// Wrap memory source in VerifiedSource => it verifies DSSE sig
	verifiedSrc := source.NewVerifiedSource(mem)

	// G) Provide searchDepth=2 => second pass finds "test" referencing artifactB
	opts := []policy.VerifyOption{
		policy.WithVerifiedSource(verifiedSrc),
		policy.WithSearchDepth(2),
		policy.WithSubjectDigests(subjectDigests),
	}

	// H) Verify => should pass if we do NOT skip memory searches at depth>0
	passed, results, err := pol.Verify(ctx, opts...)
	require.NoError(t, err, "unexpected error verifying policy")

	require.True(t, passed,
		"Expected multi-depth search to discover test referencing artifactB. Got results: %+v",
		results,
	)

	_ = verifier // ephemeral if you want to do more checks outside policy
}
