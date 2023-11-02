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
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/policy"
	"github.com/in-toto/go-witness/slsa"
	"github.com/in-toto/go-witness/source"
	"github.com/in-toto/go-witness/timestamp"
)

const (
	Name    = "policyverify"
	Type    = slsa.VerificationSummaryPredicate
	RunType = attestation.ExecuteRunType
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
	slsa.VerificationSummary

	policyTimestampAuthorities []timestamp.TimestampVerifier
	policyCARoots              []*x509.Certificate
	policyCAIntermediates      []*x509.Certificate
	policyEnvelope             dsse.Envelope
	policyVerifiers            []cryptoutil.Verifier
	collectionSource           source.Sourcer
	subjectDigests             []string

	// cert constraint options for policy envelope verification
	policyCommonName    string
	policyDNSNames      []string
	policyEmails        []string
	policyOrganizations []string
	policyURIs          []string
}

type Option func(*Attestor)

func VerifyWithPolicyEnvelope(policyEnvelope dsse.Envelope) Option {
	return func(a *Attestor) {
		a.policyEnvelope = policyEnvelope
	}
}

func VerifyWithPolicyVerifiers(policyVerifiers []cryptoutil.Verifier) Option {
	return func(a *Attestor) {
		a.policyVerifiers = append(a.policyVerifiers, policyVerifiers...)
	}
}

func VerifyWithSubjectDigests(subjectDigests []cryptoutil.DigestSet) Option {
	return func(a *Attestor) {
		for _, set := range subjectDigests {
			for _, digest := range set {
				a.subjectDigests = append(a.subjectDigests, digest)
			}
		}
	}
}

func VerifyWithCollectionSource(source source.Sourcer) Option {
	return func(a *Attestor) {
		a.collectionSource = source
	}
}

func VerifyWithPolicyTimestampAuthorities(authorities []timestamp.TimestampVerifier) Option {
	return func(a *Attestor) {
		a.policyTimestampAuthorities = authorities
	}
}

func VerifyWithPolicyCARoots(roots []*x509.Certificate) Option {
	return func(a *Attestor) {
		a.policyCARoots = roots
	}
}

func VerifyWithPolicyCAIntermediates(intermediates []*x509.Certificate) Option {
	return func(a *Attestor) {
		a.policyCAIntermediates = intermediates
	}
}

func VerifyWithPolicyCertConstraints(commonName string, dnsNames []string, emails []string, organizations []string, uris []string) Option {
	return func(a *Attestor) {
		a.policyCommonName = commonName
		a.policyDNSNames = dnsNames
		a.policyEmails = emails
		a.policyOrganizations = organizations
		a.policyURIs = uris
	}
}

func New(opts ...Option) *Attestor {
	a := &Attestor{
		policyCommonName:    "*",
		policyDNSNames:      []string{"*"},
		policyOrganizations: []string{"*"},
		policyURIs:          []string{"*"},
		policyEmails:        []string{"*"},
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

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	if err := verifyPolicySignature(ctx.Context(), a); err != nil {
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

	accepted := true
	policyResult, policyErr := pol.Verify(ctx.Context(), policy.WithSubjectDigests(a.subjectDigests), policy.WithVerifiedSource(verifiedSource))
	if _, ok := policyErr.(policy.ErrPolicyDenied); ok {
		accepted = false
	} else if policyErr != nil {
		return fmt.Errorf("failed to verify policy: %w", err)
	}

	a.VerificationSummary, err = verificationSummaryFromResults(ctx, a.policyEnvelope, policyResult, accepted)
	if err != nil {
		return fmt.Errorf("failed to generate verification summary: %w", err)
	}

	return nil
}

func verificationSummaryFromResults(ctx *attestation.AttestationContext, policyEnvelope dsse.Envelope, policyResult policy.PolicyResult, accepted bool) (slsa.VerificationSummary, error) {
	inputAttestations := make([]slsa.ResourceDescriptor, 0, len(policyResult.EvidenceByStep))
	for _, input := range policyResult.EvidenceByStep {
		for _, attestation := range input {
			digest, err := cryptoutil.CalculateDigestSetFromBytes(attestation.Envelope.Payload, ctx.Hashes())
			if err != nil {
				log.Debugf("failed to calculate evidence hash: %v", err)
				continue
			}

			inputAttestations = append(inputAttestations, slsa.ResourceDescriptor{
				URI:    attestation.Reference,
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
			URI:    policyDigest[cryptoutil.DigestValue{Hash: crypto.SHA256, GitOID: false}], //TODO: find a better value for this...
			Digest: policyDigest,
		},
		InputAttestations:  inputAttestations,
		VerificationResult: verificationResult,
	}, nil
}

func verifyPolicySignature(ctx context.Context, vo *Attestor) error {
	passedPolicyVerifiers, err := vo.policyEnvelope.Verify(dsse.VerifyWithVerifiers(vo.policyVerifiers...), dsse.VerifyWithTimestampVerifiers(vo.policyTimestampAuthorities...), dsse.VerifyWithRoots(vo.policyCARoots...), dsse.VerifyWithIntermediates(vo.policyCAIntermediates...))
	if err != nil {
		return fmt.Errorf("could not verify policy: %w", err)
	}

	var passed bool
	for _, verifier := range passedPolicyVerifiers {
		kid, err := verifier.Verifier.KeyID()
		if err != nil {
			return fmt.Errorf("could not get verifier key id: %w", err)
		}

		var f policy.Functionary
		trustBundle := make(map[string]policy.TrustBundle)
		if _, ok := verifier.Verifier.(*cryptoutil.X509Verifier); ok {
			rootIDs := make([]string, 0)
			for _, root := range vo.policyCARoots {
				id := base64.StdEncoding.EncodeToString(root.Raw)
				rootIDs = append(rootIDs, id)
				trustBundle[id] = policy.TrustBundle{
					Root: root,
				}
			}

			f = policy.Functionary{
				Type: "root",
				CertConstraint: policy.CertConstraint{
					Roots:         rootIDs,
					CommonName:    vo.policyCommonName,
					URIs:          vo.policyURIs,
					Emails:        vo.policyEmails,
					Organizations: vo.policyOrganizations,
					DNSNames:      vo.policyDNSNames,
				},
			}

		} else {
			f = policy.Functionary{
				Type:        "key",
				PublicKeyID: kid,
			}
		}

		err = f.Validate(verifier.Verifier, trustBundle)
		if err != nil {
			log.Debugf("Policy Verifier %s failed failed to match supplied constraints: %w, continuing...", kid, err)
			continue
		}
		passed = true
	}

	if !passed {
		return fmt.Errorf("no policy verifiers passed verification")
	} else {
		return nil
	}
}
