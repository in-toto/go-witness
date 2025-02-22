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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/commandrun"
	"github.com/in-toto/go-witness/attestation/material"
	"github.com/in-toto/go-witness/attestation/product"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/policy"
	"github.com/in-toto/go-witness/source"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestVerify(t *testing.T) {
	testPolicy, functionarySigner := makePolicyWithPublicKeyFunctionary(t)
	policyEnvelope, _, policyVerifier := signPolicyRSA(t, testPolicy)
	workingDir := t.TempDir()

	step1Result, err := Run(
		"step01",
		RunWithSigners(functionarySigner),
		RunWithAttestors([]attestation.Attestor{
			material.New(),
			commandrun.New(
				commandrun.WithCommand([]string{"bash", "-c", "echo 'test01' > test.txt"}),
			),
			product.New(),
		}),
		RunWithAttestationOpts(
			attestation.WithWorkingDir(workingDir),
		),
	)
	require.NoError(t, err)

	subjects := []cryptoutil.DigestSet{}
	artifactSubject, err := cryptoutil.CalculateDigestSetFromFile(
		filepath.Join(workingDir, "test.txt"),
		[]cryptoutil.DigestValue{
			{
				GitOID: false,
				Hash:   crypto.SHA256,
			},
		},
	)
	require.NoError(t, err)
	subjects = append(subjects, artifactSubject)

	step2Result, err := Run(
		"step02",
		RunWithSigners(functionarySigner),
		RunWithAttestors([]attestation.Attestor{
			material.New(),
			commandrun.New(
				commandrun.WithCommand([]string{"bash", "-c", "echo 'test02' >> test.txt"}),
			),
			product.New(),
		}),
		RunWithAttestationOpts(
			attestation.WithWorkingDir(workingDir),
		),
	)
	require.NoError(t, err)

	artifactSubject, err = cryptoutil.CalculateDigestSetFromFile(
		filepath.Join(workingDir, "test.txt"),
		[]cryptoutil.DigestValue{
			{
				GitOID: false,
				Hash:   crypto.SHA256,
			},
		},
	)
	require.NoError(t, err)
	subjects = append(subjects, artifactSubject)

	t.Run("Pass", func(t *testing.T) {
		memorySource := source.NewMemorySource()
		require.NoError(t, memorySource.LoadEnvelope("step01", step1Result.SignedEnvelope))
		require.NoError(t, memorySource.LoadEnvelope("step02", step2Result.SignedEnvelope))

		results, err := Verify(
			context.Background(),
			policyEnvelope,
			[]cryptoutil.Verifier{policyVerifier},
			VerifyWithCollectionSource(memorySource),
			VerifyWithSubjectDigests(subjects),
		)

		require.NoError(t, err, fmt.Sprintf("failed with results: %+v", results))
	})

	t.Run("Fail with missing collection", func(t *testing.T) {
		memorySource := source.NewMemorySource()
		require.NoError(t, memorySource.LoadEnvelope("step01", step1Result.SignedEnvelope))

		results, err := Verify(
			context.Background(),
			policyEnvelope,
			[]cryptoutil.Verifier{policyVerifier},
			VerifyWithCollectionSource(memorySource),
			VerifyWithSubjectDigests(subjects),
		)

		require.Error(t, err, fmt.Sprintf("passed with results: %+v", results))
	})

	t.Run("Fail with missing attestation", func(t *testing.T) {
		functionaryVerifier, err := functionarySigner.Verifier()
		require.NoError(t, err)
		policyFunctionary, policyPk := functionaryFromVerifier(t, functionaryVerifier)
		failPolicy := makePolicy(policyFunctionary, policyPk, map[string]policy.Root{})

		step1 := failPolicy.Steps["step01"]
		step1.Attestations = append(step1.Attestations, policy.Attestation{Type: "nonexistent atttestation"})
		failPolicy.Steps["step01"] = step1
		failPolicyEnvelope, _, failPolicyVerifier := signPolicyRSA(t, failPolicy)

		memorySource := source.NewMemorySource()
		require.NoError(t, memorySource.LoadEnvelope("step01", step1Result.SignedEnvelope))
		require.NoError(t, memorySource.LoadEnvelope("step02", step2Result.SignedEnvelope))

		results, err := Verify(
			context.Background(),
			failPolicyEnvelope,
			[]cryptoutil.Verifier{failPolicyVerifier},
			VerifyWithCollectionSource(memorySource),
			VerifyWithSubjectDigests(subjects),
		)

		require.Error(t, err, fmt.Sprintf("passed with results: %+v", results))
	})

	t.Run("Fail with incorrect signer", func(t *testing.T) {
		functionaryVerifier, err := functionarySigner.Verifier()
		require.NoError(t, err)
		policyFunctionary, policyPk := functionaryFromVerifier(t, functionaryVerifier)
		failPolicy := makePolicy(policyFunctionary, policyPk, map[string]policy.Root{})

		// create a new key and functionary, and replace the step's functionary with it.
		// the attestation would not have been signed with this key, so verification should fail.
		newSigner := createTestRSAKey(t)
		newVerifier, err := newSigner.Verifier()
		require.NoError(t, err)
		failPolicyFunctionary, failPolicyPk := functionaryFromVerifier(t, newVerifier)
		failPolicy.PublicKeys[failPolicyPk.KeyID] = failPolicyPk
		step1 := failPolicy.Steps["step01"]
		step1.Functionaries = []policy.Functionary{failPolicyFunctionary}
		failPolicy.Steps["step01"] = step1
		failPolicyEnvelope, _, failPolicyVerifier := signPolicyRSA(t, failPolicy)

		memorySource := source.NewMemorySource()
		require.NoError(t, memorySource.LoadEnvelope("step01", step1Result.SignedEnvelope))
		require.NoError(t, memorySource.LoadEnvelope("step02", step2Result.SignedEnvelope))

		results, err := Verify(
			context.Background(),
			failPolicyEnvelope,
			[]cryptoutil.Verifier{failPolicyVerifier},
			VerifyWithCollectionSource(memorySource),
			VerifyWithSubjectDigests(subjects),
		)

		require.Error(t, err, fmt.Sprintf("passed with results: %+v", results))
	})
}

func TestBackRefs(t *testing.T) {
	registerDummyAttestors()
	testPolicy, functionarySigner := makePolicyWithPublicKeyFunctionary(t)
	policyEnvelope, _, policyVerifier := signPolicyRSA(t, testPolicy)
	workingDir := t.TempDir()

	step1Result, err := Run(
		"step01",
		RunWithSigners(functionarySigner),
		RunWithAttestors([]attestation.Attestor{
			material.New(),
			&dummySubjectAttestor{Data: "test"},
			commandrun.New(
				commandrun.WithCommand([]string{"bash", "-c", "echo 'test01' > test.txt"}),
			),
			product.New(),
		}),
		RunWithAttestationOpts(
			attestation.WithWorkingDir(workingDir),
		),
	)
	require.NoError(t, err)

	step2Result, err := Run(
		"step02",
		RunWithSigners(functionarySigner),
		RunWithAttestors([]attestation.Attestor{
			material.New(),
			&dummyBackrefAttestor{},
			commandrun.New(
				commandrun.WithCommand([]string{"bash", "-c", "echo 'test02' >> test.txt"}),
			),
			product.New(),
		}),
		RunWithAttestationOpts(
			attestation.WithWorkingDir(workingDir),
		),
	)
	require.NoError(t, err)

	artifactSubject, err := cryptoutil.CalculateDigestSetFromFile(
		filepath.Join(workingDir, "test.txt"),
		[]cryptoutil.DigestValue{
			{
				GitOID: false,
				Hash:   crypto.SHA256,
			},
		},
	)
	require.NoError(t, err)
	memorySource := source.NewMemorySource()
	require.NoError(t, memorySource.LoadEnvelope("step01", step1Result.SignedEnvelope))
	require.NoError(t, memorySource.LoadEnvelope("step02", step2Result.SignedEnvelope))

	results, err := Verify(
		context.Background(),
		policyEnvelope,
		[]cryptoutil.Verifier{policyVerifier},
		VerifyWithCollectionSource(memorySource),
		VerifyWithSubjectDigests([]cryptoutil.DigestSet{artifactSubject}),
	)

	require.NoError(t, err, fmt.Sprintf("failed with results: %+v", results))
}

func makePolicy(functionary policy.Functionary, publicKey policy.PublicKey, roots map[string]policy.Root) policy.PolicyV1 {
	step01 := policy.Step{
		Name:          "step01",
		Functionaries: []policy.Functionary{functionary},
		Attestations:  []policy.Attestation{{Type: commandrun.Type}},
	}

	step02 := policy.Step{
		Name:          "step02",
		Functionaries: []policy.Functionary{functionary},
		Attestations:  []policy.Attestation{{Type: commandrun.Type}},
		ArtifactsFrom: []string{"step01"},
	}

	p := policy.PolicyV1{
		Expires:    metav1.Time{Time: time.Now().Add(1 * time.Hour)},
		PublicKeys: map[string]policy.PublicKey{},
		Steps:      map[string]policy.Step{},
	}

	if functionary.CertConstraint.Roots != nil {
		p.Roots = roots
	}

	p.Steps = make(map[string]policy.Step)
	p.Steps[step01.Name] = step01
	p.Steps[step02.Name] = step02

	if publicKey.KeyID != "" {
		p.PublicKeys[publicKey.KeyID] = publicKey
	}

	return p
}

func makePolicyWithPublicKeyFunctionary(t *testing.T) (policy.Policy, cryptoutil.Signer) {
	signer := createTestRSAKey(t)
	verifier, err := signer.Verifier()
	require.NoError(t, err)
	functionary, pk := functionaryFromVerifier(t, verifier)
	p := makePolicy(functionary, pk, nil)
	return p, signer
}

func functionaryFromVerifier(t *testing.T, v cryptoutil.Verifier) (policy.Functionary, policy.PublicKey) {
	keyID, err := v.KeyID()
	require.NoError(t, err)
	keyBytes, err := v.Bytes()
	require.NoError(t, err)
	return policy.Functionary{
			Type:        "PublicKey",
			PublicKeyID: keyID,
		},
		policy.PublicKey{
			KeyID: keyID,
			Key:   keyBytes,
		}
}

func signPolicyRSA(t *testing.T, p policy.Policy) (dsse.Envelope, cryptoutil.Signer, cryptoutil.Verifier) {
	signer := createTestRSAKey(t)
	env := signPolicy(t, p, signer)
	verifier, err := signer.Verifier()
	require.NoError(t, err)
	return env, signer, verifier
}

func signPolicy(t *testing.T, p policy.Policy, signer cryptoutil.Signer) dsse.Envelope {
	pBytes, err := json.Marshal(p)
	require.NoError(t, err)
	reader := bytes.NewReader(pBytes)
	outBytes := []byte{}
	writer := bytes.NewBuffer(outBytes)
	require.NoError(t, Sign(reader, string(policy.WitnessPolicyPredicate), writer, dsse.SignWithSigners(signer)))
	env := dsse.Envelope{}
	require.NoError(t, json.Unmarshal(writer.Bytes(), &env))
	return env
}

func createTestRSAKey(t *testing.T) cryptoutil.Signer {
	privKey, err := rsa.GenerateKey(rand.Reader, 512)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
	return signer
}

const (
	dummySubjectAttestorName = "subject attestor"
	dummySubjectAttestorType = "test/subjectattestor"
	dummyBackrefAttestorName = "backref attestor"
	dummyBackrefAttestorType = "test/backrefattestor"
	matchSubjectName         = "matchSubject"
)

// policy verification currently needs attestors to be registers to properly validate them
func registerDummyAttestors() {
	attestation.RegisterAttestation(dummyBackrefAttestorName, dummyBackrefAttestorType, attestation.PreMaterialRunType, func() attestation.Attestor { return &dummyBackrefAttestor{} })
	attestation.RegisterAttestation(dummySubjectAttestorName, dummySubjectAttestorType, attestation.PreMaterialRunType, func() attestation.Attestor { return &dummySubjectAttestor{} })
}

// dummySubjectAttestor is a test attestor used to create a subject on an attestation.
// this subject will be used to discover this attestor when searching by back ref subjects
// from a subsequent step in the policy.
type dummySubjectAttestor struct {
	Data string
}

func (a *dummySubjectAttestor) Name() string {
	return dummySubjectAttestorName
}

func (a *dummySubjectAttestor) Type() string {
	return dummySubjectAttestorType
}

func (a *dummySubjectAttestor) RunType() attestation.RunType {
	return attestation.PreMaterialRunType
}

func (a *dummySubjectAttestor) Attest(ctx *attestation.AttestationContext) error {
	return nil
}

func (a *dummySubjectAttestor) Schema() *jsonschema.Schema {
	return nil
}

func (a *dummySubjectAttestor) Subjects() map[string]cryptoutil.DigestSet {
	return map[string]cryptoutil.DigestSet{
		matchSubjectName: {
			{Hash: crypto.SHA256}: "abcde",
		},
	}
}

// dummyBackrefAttestor is a test attestor used to expose a back ref subject, used to find
// attestations from preceding steps.
// for a practical example of this, consider policy that enforces two steps: a test step and a build step that produces a binary.
// when we begin policy evaluation, we only know two things: the hash of the binary, and the steps the policy expects.
// when we look up attestations that contain a product matching the binary's hash and satisfies the build step of the policy.
// that build attestation may contain a back ref subject that is the hash of the git commit, which also appears on the test attestation.
// we can then use this back ref subject to link the test attestation to the build attestation during policy evaluation.
type dummyBackrefAttestor struct{}

func (a *dummyBackrefAttestor) Name() string {
	return dummyBackrefAttestorName
}

func (a *dummyBackrefAttestor) Type() string {
	return dummyBackrefAttestorType
}

func (a *dummyBackrefAttestor) RunType() attestation.RunType {
	return attestation.PreMaterialRunType
}

func (a *dummyBackrefAttestor) Attest(ctx *attestation.AttestationContext) error {
	return nil
}

func (a *dummyBackrefAttestor) Schema() *jsonschema.Schema {
	return nil
}

func (a *dummyBackrefAttestor) BackRefs() map[string]cryptoutil.DigestSet {
	return map[string]cryptoutil.DigestSet{
		matchSubjectName: {
			{Hash: crypto.SHA256}: "abcde",
		},
	}
}
