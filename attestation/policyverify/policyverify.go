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

package policyverify

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/dsse"
	ipolicy "github.com/in-toto/go-witness/internal/policy"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/policy"
	"github.com/in-toto/go-witness/slsa"
	"github.com/in-toto/go-witness/source"
	"github.com/in-toto/go-witness/timestamp"
)

const (
	Name    = "policyverify"
	Type    = slsa.VerificationSummaryPredicate
	RunType = attestation.VerifyRunType
)

var (
	_ attestation.Subjecter = &Attestor{}
	_ attestation.Attestor  = &Attestor{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type Attestor struct {
	*ipolicy.VerifyPolicySignatureOptions
	slsa.VerificationSummary

	stepResults      map[string]policy.StepResult
	policyEnvelope   dsse.Envelope
	collectionSource source.Sourcer
	subjectDigests   []string
}

type Option func(*Attestor)

func VerifyWithPolicyVerificationOptions(opts ...ipolicy.Option) Option {
	return func(a *Attestor) {
		for _, opt := range opts {
			opt(a.VerifyPolicySignatureOptions)
		}
	}
}

func VerifyWithPolicyEnvelope(policyEnvelope dsse.Envelope) Option {
	return func(a *Attestor) {
		a.policyEnvelope = policyEnvelope
	}
}

func VerifyWithSubjectDigests(subjectDigests []cryptoutil.DigestSet) Option {
	return func(vo *Attestor) {
		for _, set := range subjectDigests {
			for _, digest := range set {
				vo.subjectDigests = append(vo.subjectDigests, digest)
			}
		}
	}
}

func VerifyWithCollectionSource(source source.Sourcer) Option {
	return func(vo *Attestor) {
		vo.collectionSource = source
	}
}

func New(opts ...Option) *Attestor {
	vps := ipolicy.NewVerifyPolicySignatureOptions()
	a := &Attestor{
		VerifyPolicySignatureOptions: vps,
	}

	for _, opt := range opts {
		opt(a)
	}

	return a
}

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) Type() string {
	return Type
}

func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	subjects := map[string]cryptoutil.DigestSet{}
	for _, digest := range a.subjectDigests {
		subjects[fmt.Sprintf("artifact:%v", digest)] = cryptoutil.DigestSet{
			cryptoutil.DigestValue{Hash: crypto.SHA256, GitOID: false}: digest,
		}
	}

	subjects[fmt.Sprintf("policy:%v", a.VerificationSummary.Policy.URI)] = a.VerificationSummary.Policy.Digest
	return subjects
}

func (a *Attestor) StepResults() map[string]policy.StepResult {
	return a.stepResults
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	if err := ipolicy.VerifyPolicySignature(ctx.Context(), a.policyEnvelope, a.VerifyPolicySignatureOptions); err != nil {
		return fmt.Errorf("failed to verify policy signature: %w", err)
	}

	log.Info("policy signature verified")

	pol := policy.Policy{}
	if err := json.Unmarshal(a.policyEnvelope.Payload, &pol); err != nil {
		return fmt.Errorf("failed to unmarshal policy from envelope: %w", err)
	}

	pubKeysById, err := pol.PublicKeyVerifiers()
	if err != nil {
		return fmt.Errorf("failed to get public keys from policy: %w", err)
	}

	pubkeys := make([]cryptoutil.Verifier, 0)
	for _, pubkey := range pubKeysById {
		pubkeys = append(pubkeys, pubkey)
	}

	trustBundlesById, err := pol.TrustBundles()
	if err != nil {
		return fmt.Errorf("failed to load policy trust bundles: %w", err)
	}

	roots := make([]*x509.Certificate, 0)
	intermediates := make([]*x509.Certificate, 0)
	for _, trustBundle := range trustBundlesById {
		roots = append(roots, trustBundle.Root)
		intermediates = append(intermediates, intermediates...)
	}

	timestampAuthoritiesById, err := pol.TimestampAuthorityTrustBundles()
	if err != nil {
		return fmt.Errorf("failed to load policy timestamp authorities: %w", err)
	}

	timestampVerifiers := make([]timestamp.TimestampVerifier, 0)
	for _, timestampAuthority := range timestampAuthoritiesById {
		certs := []*x509.Certificate{timestampAuthority.Root}
		certs = append(certs, timestampAuthority.Intermediates...)
		timestampVerifiers = append(timestampVerifiers, timestamp.NewVerifier(timestamp.VerifyWithCerts(certs)))
	}

	verifiedSource := source.NewVerifiedSource(
		a.collectionSource,
		dsse.VerifyWithVerifiers(pubkeys...),
		dsse.VerifyWithRoots(roots...),
		dsse.VerifyWithIntermediates(intermediates...),
		dsse.VerifyWithTimestampVerifiers(timestampVerifiers...),
	)

	accepted, stepResults, policyErr := pol.Verify(ctx.Context(), policy.WithSubjectDigests(a.subjectDigests), policy.WithVerifiedSource(verifiedSource))
	if policyErr != nil {
		// TODO: log stepResults
		return fmt.Errorf("failed to verify policy: %w", policyErr)
	}

	a.stepResults = stepResults

	a.VerificationSummary, err = verificationSummaryFromResults(ctx, a.policyEnvelope, stepResults, accepted)
	if err != nil {
		return fmt.Errorf("failed to generate verification summary: %w", err)
	}

	return nil
}

func verificationSummaryFromResults(ctx *attestation.AttestationContext, policyEnvelope dsse.Envelope, stepResults map[string]policy.StepResult, accepted bool) (slsa.VerificationSummary, error) {
	inputAttestations := make([]slsa.ResourceDescriptor, 0, len(stepResults))
	for _, step := range stepResults {
		for _, collection := range step.Passed {
			digest, err := cryptoutil.CalculateDigestSetFromBytes(collection.Envelope.Payload, ctx.Hashes())
			if err != nil {
				log.Debugf("failed to calculate evidence hash: %v", err)
				continue
			}

			inputAttestations = append(inputAttestations, slsa.ResourceDescriptor{
				URI:    collection.Reference,
				Digest: digest,
			})
		}
	}

	policyDigest, err := cryptoutil.CalculateDigestSetFromBytes(policyEnvelope.Payload, ctx.Hashes())
	if err != nil {
		return slsa.VerificationSummary{}, fmt.Errorf("failed to calculate policy digest: %w", err)
	}

	verificationResult := slsa.FailedVerificationResult
	if accepted {
		verificationResult = slsa.PassedVerificationResult
	}

	return slsa.VerificationSummary{
		Verifier: slsa.Verifier{
			ID: "witness",
		},
		TimeVerified: time.Now(),
		Policy: slsa.ResourceDescriptor{
			URI:    policy.PolicyPredicate,
			Digest: policyDigest,
		},
		InputAttestations:  inputAttestations,
		VerificationResult: verificationResult,
	}, nil
}
