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
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestVerify(t *testing.T) {
	testPolicy, functionarySigner := makepolicyRSA(t)
	policyEnvelope, policySigner := signPolicyRSA(t, testPolicy)
	policyVerifier, err := policySigner.Verifier()
	require.NoError(t, err)
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
		functionaryKeyID, err := functionaryVerifier.KeyID()
		require.NoError(t, err)
		functionaryPublicKey, err := functionaryVerifier.Bytes()
		require.NoError(t, err)
		failPolicy := makepolicy(policy.Functionary{
			Type:        "PublicKey",
			PublicKeyID: functionaryKeyID,
		},
			policy.PublicKey{
				KeyID: functionaryKeyID,
				Key:   functionaryPublicKey,
			},
			map[string]policy.Root{},
		)

		step1 := failPolicy.Steps["step01"]
		step1.Attestations = append(step1.Attestations, policy.Attestation{Type: "nonexistent atttestation"})
		failPolicy.Steps["step01"] = step1
		failPolicyEnvelope, failPolicySigner := signPolicyRSA(t, failPolicy)
		failPolicyVerifier, err := failPolicySigner.Verifier()
		require.NoError(t, err)

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

func makepolicy(functionary policy.Functionary, publicKey policy.PublicKey, roots map[string]policy.Root) policy.Policy {
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

	p := policy.Policy{
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

func makepolicyRSA(t *testing.T) (policy.Policy, cryptoutil.Signer) {
	signer, err := createTestRSAKey()
	require.NoError(t, err)
	verifier, err := signer.Verifier()
	require.NoError(t, err)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)
	functionary := policy.Functionary{
		Type:        "PublicKey",
		PublicKeyID: keyID,
	}

	pub, err := verifier.Bytes()
	require.NoError(t, err)

	pk := policy.PublicKey{
		KeyID: keyID,
		Key:   pub,
	}

	p := makepolicy(functionary, pk, nil)
	return p, signer
}

func signPolicyRSA(t *testing.T, p policy.Policy) (dsse.Envelope, cryptoutil.Signer) {
	signer, err := createTestRSAKey()
	require.NoError(t, err)
	pBytes, err := json.Marshal(p)
	require.NoError(t, err)
	reader := bytes.NewReader(pBytes)
	outBytes := []byte{}
	writer := bytes.NewBuffer(outBytes)
	require.NoError(t, Sign(reader, policy.PolicyPredicate, writer, dsse.SignWithSigners(signer)))
	env := dsse.Envelope{}
	require.NoError(t, json.Unmarshal(writer.Bytes(), &env))
	return env, signer
}

func createTestRSAKey() (cryptoutil.Signer, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		return nil, err
	}

	signer := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
	return signer, nil
}
