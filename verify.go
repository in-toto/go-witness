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

package witness

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/policyverify"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/dsse"
	ipolicy "github.com/in-toto/go-witness/internal/policy"
	"github.com/in-toto/go-witness/policy"
	"github.com/in-toto/go-witness/signer"
	"github.com/in-toto/go-witness/slsa"
	"github.com/in-toto/go-witness/source"
	"github.com/in-toto/go-witness/timestamp"
	"github.com/sigstore/fulcio/pkg/certificate"
)

func VerifySignature(r io.Reader, verifiers ...cryptoutil.Verifier) (dsse.Envelope, error) {
	decoder := json.NewDecoder(r)
	envelope := dsse.Envelope{}
	if err := decoder.Decode(&envelope); err != nil {
		return envelope, fmt.Errorf("failed to parse dsse envelope: %w", err)
	}

	_, err := envelope.Verify(dsse.VerifyWithVerifiers(verifiers...))
	return envelope, err
}

type verifyOptions struct {
	attestorOptions              []policyverify.Option
	verifyPolicySignatureOptions []ipolicy.Option
	runOptions                   []RunOption
	signers                      []cryptoutil.Signer
	kmsProviderOptions           map[string][]func(signer.SignerProvider) (signer.SignerProvider, error)
}

type VerifyOption func(*verifyOptions)

// VerifyWithSigners will configure the provided signers to be used to sign a DSSE envelope with the resulting
// policyverify attestor. See VerifyWithRunOptions for additional options.
func VerifyWithSigners(signers ...cryptoutil.Signer) VerifyOption {
	return func(vo *verifyOptions) {
		vo.signers = append(vo.signers, signers...)
	}
}

// VerifyWithSubjectDigests configured the "seed" subject digests to start evaluating a policy. This is typically
// the digest of the software artifact or some other identifying digest.
func VerifyWithSubjectDigests(subjectDigests []cryptoutil.DigestSet) VerifyOption {
	return func(vo *verifyOptions) {
		vo.attestorOptions = append(vo.attestorOptions, policyverify.VerifyWithSubjectDigests(subjectDigests))
	}
}

// VerifyWithCollectionSource configures the policy engine's sources for signed attestation collections.
// For example: disk or archivista are two typical sources.
func VerifyWithCollectionSource(source source.Sourcer) VerifyOption {
	return func(vo *verifyOptions) {
		vo.attestorOptions = append(vo.attestorOptions, policyverify.VerifyWithCollectionSource(source))
	}
}

// VerifyWithAttestorOptions forwards the provided options to the policyverify attestor.
func VerifyWithAttestorOptions(opts ...policyverify.Option) VerifyOption {
	return func(vo *verifyOptions) {
		vo.attestorOptions = append(vo.attestorOptions, opts...)
	}
}

// VerifyWithRunOptions forwards the provided RunOptions to the Run function that Verify calls.
func VerifyWithRunOptions(opts ...RunOption) VerifyOption {
	return func(vo *verifyOptions) {
		vo.runOptions = append(vo.runOptions, opts...)
	}
}

func VerifyWithPolicyFulcioCertExtensions(extensions certificate.Extensions) VerifyOption {
	return func(vo *verifyOptions) {
		vo.verifyPolicySignatureOptions = append(vo.verifyPolicySignatureOptions, ipolicy.VerifyWithPolicyFulcioCertExtensions(extensions))
	}
}

func VerifyWithPolicyCertConstraints(commonName string, dnsNames []string, emails []string, organizations []string, uris []string) VerifyOption {
	return func(vo *verifyOptions) {
		vo.verifyPolicySignatureOptions = append(vo.verifyPolicySignatureOptions, ipolicy.VerifyWithPolicyCertConstraints(commonName, dnsNames, emails, organizations, uris))
	}
}

func VerifyWithPolicyTimestampAuthorities(verifiers []timestamp.TimestampVerifier) VerifyOption {
	return func(vo *verifyOptions) {
		vo.verifyPolicySignatureOptions = append(vo.verifyPolicySignatureOptions, ipolicy.VerifyWithPolicyTimestampAuthorities(verifiers))
	}
}

func VerifyWithPolicyCARoots(certs []*x509.Certificate) VerifyOption {
	return func(vo *verifyOptions) {
		vo.verifyPolicySignatureOptions = append(vo.verifyPolicySignatureOptions, ipolicy.VerifyWithPolicyCARoots(certs))
	}
}

func VerifyWithPolicyCAIntermediates(certs []*x509.Certificate) VerifyOption {
	return func(vo *verifyOptions) {
		vo.verifyPolicySignatureOptions = append(vo.verifyPolicySignatureOptions, ipolicy.VerifyWithPolicyCAIntermediates(certs))
	}
}

func VerifyWithKMSProviderOptions(opts map[string][]func(signer.SignerProvider) (signer.SignerProvider, error)) VerifyOption {
	return func(vo *verifyOptions) {
		vo.kmsProviderOptions = opts
	}
}

type VerifyResult struct {
	RunResult
	VerificationSummary slsa.VerificationSummary
	StepResults         map[string]policy.StepResult
}

// Verify verifies a set of attestations against a provided policy. The set of attestations that satisfy the policy will be returned
// if verifiation is successful.
func Verify(ctx context.Context, policyEnvelope dsse.Envelope, policyVerifiers []cryptoutil.Verifier, opts ...VerifyOption) (VerifyResult, error) {
	vo := verifyOptions{}

	for _, opt := range opts {
		opt(&vo)
	}

	vo.verifyPolicySignatureOptions = append(vo.verifyPolicySignatureOptions, ipolicy.VerifyWithPolicyVerifiers(policyVerifiers))
	vo.attestorOptions = append(vo.attestorOptions, policyverify.VerifyWithPolicyEnvelope(policyEnvelope), policyverify.VerifyWithPolicyVerificationOptions(vo.verifyPolicySignatureOptions...))
	if len(vo.signers) > 0 {
		vo.runOptions = append(vo.runOptions, RunWithSigners(vo.signers...))
	} else {
		vo.runOptions = append(vo.runOptions, RunWithInsecure(true))
	}

	// hacky solution to ensure the verification attestor is run through the attestation context
	vo.runOptions = append(vo.runOptions,
		RunWithAttestors(
			[]attestation.Attestor{
				policyverify.New(
					append(
						[]policyverify.Option{policyverify.VerifyWithKMSProviderOptions(vo.kmsProviderOptions)},
						vo.attestorOptions...,
					)...,
				),
			},
		),
	)

	runResult, err := Run("policyverify", vo.runOptions...)
	if err != nil {
		return VerifyResult{}, err
	}

	vr := VerifyResult{
		RunResult: runResult,
	}

	for _, att := range runResult.Collection.Attestations {
		if att.Type == slsa.VerificationSummaryPredicate {
			verificationAttestor, ok := att.Attestation.(*policyverify.Attestor)
			if !ok {
				return VerifyResult{}, fmt.Errorf("unknown attestor %T", att.Attestation)
			}

			vr.StepResults = verificationAttestor.StepResults()
			vr.VerificationSummary = verificationAttestor.VerificationSummary
			break
		}
	}

	if vr.VerificationSummary.VerificationResult != slsa.PassedVerificationResult {
		return vr, fmt.Errorf("policy verification failed")
	}

	return vr, nil
}
