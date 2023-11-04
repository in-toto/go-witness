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
	"strings"
	"time"

	"github.com/testifysec/go-witness/attestation"
	"github.com/testifysec/go-witness/cryptoutil"
	"github.com/testifysec/go-witness/dsse"
	"github.com/testifysec/go-witness/intoto"
	"github.com/testifysec/go-witness/log"
	"github.com/testifysec/go-witness/policy"
	"github.com/testifysec/go-witness/slsa"
	"github.com/testifysec/go-witness/source"
	"github.com/testifysec/go-witness/timestamp"
)

const (
	Name = "policyverify"
	Type = slsa.VerificationSummaryPredicate
)

var (
	_ attestation.Subjecter = &Attestor{}
	_ attestation.Attestor  = &Attestor{}
)

type Attestor struct {
	slsa.VerificationSummary
	WitnessVerifyInfo WitnessVerifyInfo `json:"witnessverifyinfo,omitempty"`

	policyEnvelope   dsse.Envelope
	policyVerifiers  []cryptoutil.Verifier
	collectionSource source.Sourcer
}

type WitnessVerifyInfo struct {
	// InitialSubjectDigests is the set of subject digests passed to witness Verify to start
	// the verification process
	InitialSubjectDigests []cryptoutil.DigestSet `json:"initialsubjectdigests,omitempty"`
	// AdditionalSubjects is a set of subjects that were used during the verification process.
	AdditionalSubjects map[string]cryptoutil.DigestSet `json:"additionalsubjects,omitempty"`
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
		a.WitnessVerifyInfo.InitialSubjectDigests = append(a.WitnessVerifyInfo.InitialSubjectDigests, subjectDigests...)
	}
}

func VerifyWithCollectionSource(source source.Sourcer) Option {
	return func(a *Attestor) {
		a.collectionSource = source
	}
}

func New(opts ...Option) *Attestor {
	a := &Attestor{
		WitnessVerifyInfo: WitnessVerifyInfo{
			AdditionalSubjects:    make(map[string]cryptoutil.DigestSet),
			InitialSubjectDigests: make([]cryptoutil.DigestSet, 0),
		},
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
	return attestation.ExecuteRunType
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	subjects := map[string]cryptoutil.DigestSet{}
	for n, digestSet := range a.WitnessVerifyInfo.InitialSubjectDigests {
		subjects[fmt.Sprintf("artifact:%v", n)] = digestSet
	}

	subjects[fmt.Sprintf("policy:%v", a.VerificationSummary.Policy.URI)] = a.VerificationSummary.Policy.Digest
	for name, ds := range a.WitnessVerifyInfo.AdditionalSubjects {
		subjects[name] = ds
	}

	return subjects
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	if _, err := a.policyEnvelope.Verify(dsse.VerifyWithVerifiers(a.policyVerifiers...)); err != nil {
		return fmt.Errorf("could not verify policy: %w", err)
	}

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
		intermediates = append(intermediates, trustBundle.Intermediates...)
	}

	timestampAuthoritiesById, err := pol.TimestampAuthorityTrustBundles()
	if err != nil {
		return fmt.Errorf("failed to load policy timestamp authorities: %w", err)
	}

	timestampVerifiers := make([]dsse.TimestampVerifier, 0)
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
	policyResult, policyErr := pol.Verify(ctx.Context(), policy.WithSubjectDigests(a.WitnessVerifyInfo.InitialSubjectDigests), policy.WithVerifiedSource(verifiedSource))
	if _, ok := policyErr.(policy.ErrPolicyDenied); ok {
		accepted = false
	} else if policyErr != nil {
		return fmt.Errorf("failed to verify policy: %w", err)
	}

	a.VerificationSummary, err = verificationSummaryFromResults(ctx, a.policyEnvelope, policyResult, accepted)
	if err != nil {
		return fmt.Errorf("failed to generate verification summary: %w", err)
	}

	a.findInterestingSubjects(policyResult.EvidenceByStep)
	return nil
}

// findInterestingSubjects will search subjects of attestations used during the verification process
// for interesting subjects, and package them onto the VSA as additional subjects. This is used
// primarily to link a VSA back to a specific github or gitlab project, or an artifact hash to
// a specific tagged image.
func (a *Attestor) findInterestingSubjects(evidenceByStep map[string][]source.VerifiedCollection) {
	// imageId is especially interesting, and we only treat the other interesting subject candidates
	// as valid if we get a match on the imageId
	const imageIdSubjectPrefix = "https://witness.dev/attestations/oci/v0.1/imageid:"

	// a map of subjects we consider interesting. the value of this map is just a value we'll use
	// to repackage the subject as a subject of the VSA itself.
	interestingSubjects := map[string]string{
		"https://witness.dev/attestations/oci/v0.1/imagetag:":      "imagetag",
		"https://witness.dev/attestations/github/v0.1/projecturl:": "projecturl",
		"https://witness.dev/attestations/gitlab/v0.1/projecturl:": "projecturl",
		"https://witness.dev/attestations/git/v0.1/commithash:":    "commithash",
	}

	for _, collections := range evidenceByStep {
		for _, collection := range collections {
			candidates := make([]intoto.Subject, 0)
			matchedSubject := false

			// search through every subject on the in-toto statment. if we find any interesting subjects, we set them aside as possible candidates.
			// if we find an imageid subject that matches, we consider all the candidates to be matching subjects and add them to our list
			for _, subject := range collection.Statement.Subject {
				// if we find an image tag subject, add it to the list of candidates
				for interstingSubject, transformedSubject := range interestingSubjects {
					if strings.HasPrefix(subject.Name, interstingSubject) {
						candidates = append(candidates, intoto.Subject{
							Name:   fmt.Sprintf("%v:%v", transformedSubject, strings.TrimPrefix(subject.Name, interstingSubject)),
							Digest: subject.Digest,
						})
					}

					// if we find an imageid subject, check to see if any the digests we verified match the imageid
					if strings.HasPrefix(subject.Name, imageIdSubjectPrefix) {
						for _, imageIdDigest := range subject.Digest {
							for _, testDigestSet := range a.WitnessVerifyInfo.InitialSubjectDigests {
								for _, testImageIdDigest := range testDigestSet {
									if imageIdDigest == testImageIdDigest {
										matchedSubject = true
										candidates = append(candidates, intoto.Subject{
											Name:   fmt.Sprintf("imageid:%v", testImageIdDigest),
											Digest: subject.Digest,
										})
									}
								}
							}

							// if we found a matching imageid subject with one of our test subject digests, stop looking
							if matchedSubject {
								break
							}
						}
					}
				}

				// after we've checked all the subjects, if we found a match, add our candidates to our additional subjects
				if matchedSubject {
					for _, candidate := range candidates {
						ds := cryptoutil.DigestSet{}
						for hash, value := range candidate.Digest {
							digestValue, err := cryptoutil.DigestValueFromString(hash)
							if err != nil {
								continue
							}

							ds[digestValue] = value
						}

						a.WitnessVerifyInfo.AdditionalSubjects[candidate.Name] = ds
					}
				}
			}
		}
	}
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
