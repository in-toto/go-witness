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

package policy

import (
	"context"
	"crypto"
	"encoding/json"
	"testing"
	"time"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/commandrun"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/intoto"
	"github.com/in-toto/go-witness/source"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A step that declares no required attestations must not pass a collection unconditionally; it must
// fail closed with a reason rather than silently accepting or dropping the collection.
func TestValidateAttestationsFailsOnEmptyAttestations(t *testing.T) {
	cr := commandrun.New()
	cr.Cmd = []string{"go", "build"}
	coll := attestation.NewCollection("build", []attestation.CompletedAttestor{
		{Attestor: cr, StartTime: time.Now(), EndTime: time.Now()},
	})
	cvr := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{Collection: coll, Reference: "1"},
	}

	step := Step{Name: "build", Attestations: []Attestation{}} // no required attestations
	result := step.validateAttestations([]source.CollectionVerificationResult{cvr})

	require.Empty(t, result.Passed,
		"a step with an empty attestations list must not pass a collection")
	require.NotEmpty(t, result.Rejected,
		"a step with an empty attestations list must reject the collection, not silently drop it")
	require.ErrorContains(t, result.Rejected[0].Reason, "no required attestations",
		"the rejection must explain that an empty attestations list is not a valid gate")
}

// verifyCollectionNamed runs Verify for a step named "deploy" against a name-agnostic
// VerifiedSourcer (which returns its collection for any query, modelling a subject-only library
// source) and reports whether verification passed.
func verifyCollectionNamed(t *testing.T, collectionName string) bool {
	_, verifier, pub, err := createTestKey()
	require.NoError(t, err)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)
	pol := Policy{
		Expires:    metav1.NewTime(time.Now().Add(time.Hour)),
		PublicKeys: map[string]PublicKey{keyID: {KeyID: keyID, Key: pub}},
		Steps: map[string]Step{"deploy": {Name: "deploy",
			Functionaries: []Functionary{{Type: "PublicKey", PublicKeyID: keyID}},
			Attestations:  []Attestation{{Type: commandrun.Type}}}},
	}
	cr := commandrun.New()
	cr.Cmd = []string{"go", "build"}
	coll := attestation.NewCollection(collectionName, []attestation.CompletedAttestor{{Attestor: cr, StartTime: time.Now(), EndTime: time.Now()}})
	cj, err := json.Marshal(&coll)
	require.NoError(t, err)
	stmt, err := intoto.NewStatement(attestation.CollectionType, cj, map[string]cryptoutil.DigestSet{"x": {cryptoutil.DigestValue{Hash: crypto.SHA256}: "x"}})
	require.NoError(t, err)
	cvr := source.CollectionVerificationResult{
		Verifiers:          []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{Statement: stmt, Collection: coll, Reference: "1"},
	}
	pass, _, err := pol.Verify(context.Background(), WithSubjectDigests([]string{"x"}),
		WithVerifiedSource(newDummyVerifiedSourcer([]source.CollectionVerificationResult{cvr})))
	require.NoError(t, err)
	return pass
}

// A collection must carry the step's exact name to be validated against it. An empty collection name
// must not act as a wildcard that satisfies a differently-named step.
func TestValidateAttestationsRequiresExactCollectionName(t *testing.T) {
	require.False(t, verifyCollectionNamed(t, "some-other-step"),
		"a non-empty mismatched collection name must not satisfy step 'deploy'")
	require.False(t, verifyCollectionNamed(t, ""),
		"an empty collection name must not satisfy a differently-named step")
}

type shadowAttestor struct {
	Cmd string `json:"cmd"`
}

func (shadowAttestor) Name() string                                 { return "shadow" }
func (shadowAttestor) Type() string                                 { return "shadow" }
func (shadowAttestor) RunType() attestation.RunType                 { return attestation.PreMaterialRunType }
func (shadowAttestor) Schema() *jsonschema.Schema                   { return jsonschema.Reflect(shadowAttestor{}) }
func (shadowAttestor) Attest(*attestation.AttestationContext) error { return nil }

// The rego policy must be evaluated against every attestor of the expected type. A policy-violating
// attestor must not be able to hide behind a benign attestor of the same type appended after it.
func TestValidateAttestationsEvaluatesAllAttestorsOfType(t *testing.T) {
	denyDangerous := []byte(`package shadow
deny[msg] {
	input.cmd == "rm -rf /"
	msg := "dangerous command"
}`)

	step := Step{
		Name: "build",
		Attestations: []Attestation{
			{Type: "shadow", RegoPolicies: []RegoPolicy{{Name: "no-danger", Module: denyDangerous}}},
		},
	}

	// Same predicate type twice: the denied attestor first, a benign one appended after.
	coll := attestation.Collection{
		Name: "build",
		Attestations: []attestation.CollectionAttestation{
			{Type: "shadow", Attestation: shadowAttestor{Cmd: "rm -rf /"}},
			{Type: "shadow", Attestation: shadowAttestor{Cmd: "make"}},
		},
	}

	result := step.validateAttestations([]source.CollectionVerificationResult{
		{CollectionEnvelope: source.CollectionEnvelope{Collection: coll}},
	})

	require.Empty(t, result.Passed,
		"a collection containing a denied attestor must not pass regardless of same-type attestors appended after it")
}
