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
	"crypto/x509"
	"fmt"
	"time"

	"github.com/testifysec/go-witness/attestation"
	"github.com/testifysec/go-witness/cryptoutil"
	"github.com/testifysec/go-witness/log"
	"github.com/testifysec/go-witness/source"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const PolicyPredicate = "https://witness.testifysec.com/policy/v0.1"

// +kubebuilder:object:generate=true
type Policy struct {
	Expires              metav1.Time          `json:"expires"`
	Roots                map[string]Root      `json:"roots,omitempty"`
	TimestampAuthorities map[string]Root      `json:"timestampauthorities,omitempty"`
	PublicKeys           map[string]PublicKey `json:"publickeys,omitempty"`
	Steps                map[string]Step      `json:"steps"`
}

// +kubebuilder:object:generate=true
type Root struct {
	Certificate   []byte   `json:"certificate"`
	Intermediates [][]byte `json:"intermediates,omitempty"`
}

// +kubebuilder:object:generate=true
type PublicKey struct {
	KeyID string `json:"keyid"`
	Key   []byte `json:"key"`
}

// PublicKeyVerifiers returns verifiers for each of the policy's embedded public keys grouped by the key's ID
func (p Policy) PublicKeyVerifiers() (map[string]cryptoutil.Verifier, error) {
	verifiers := make(map[string]cryptoutil.Verifier)
	for _, key := range p.PublicKeys {
		verifier, err := cryptoutil.NewVerifierFromReader(bytes.NewReader(key.Key))
		if err != nil {
			return nil, err
		}

		keyID, err := verifier.KeyID()
		if err != nil {
			return nil, err
		}

		if keyID != key.KeyID {
			return nil, ErrKeyIDMismatch{
				Expected: key.KeyID,
				Actual:   keyID,
			}
		}

		verifiers[keyID] = verifier
	}

	return verifiers, nil
}

type TrustBundle struct {
	Root          *x509.Certificate
	Intermediates []*x509.Certificate
}

// TrustBundles returns the policy's x509 roots and intermediates grouped by the root's ID
func (p Policy) TrustBundles() (map[string]TrustBundle, error) {
	return trustBundlesFromRoots(p.Roots)
}

func (p Policy) TimestampAuthorityTrustBundles() (map[string]TrustBundle, error) {
	return trustBundlesFromRoots(p.TimestampAuthorities)
}

func trustBundlesFromRoots(roots map[string]Root) (map[string]TrustBundle, error) {
	bundles := make(map[string]TrustBundle)
	for id, root := range roots {
		bundle := TrustBundle{}
		var err error
		bundle.Root, err = cryptoutil.TryParseCertificate(root.Certificate)
		if err != nil {
			return bundles, err
		}

		for _, intBytes := range root.Intermediates {
			cert, err := cryptoutil.TryParseCertificate(intBytes)
			if err != nil {
				return bundles, err
			}

			bundle.Intermediates = append(bundle.Intermediates, cert)
		}

		bundles[id] = bundle
	}

	return bundles, nil
}

type VerifyOption func(*verifyOptions)

type verifyOptions struct {
	verifiedSource source.VerifiedSourcer
	subjectDigests []cryptoutil.DigestSet
	searchDepth    int
}

func WithVerifiedSource(verifiedSource source.VerifiedSourcer) VerifyOption {
	return func(vo *verifyOptions) {
		vo.verifiedSource = verifiedSource
	}
}

func WithSubjectDigests(subjectDigests []cryptoutil.DigestSet) VerifyOption {
	return func(vo *verifyOptions) {
		vo.subjectDigests = subjectDigests
	}
}

func WithSearchDepth(depth int) VerifyOption {
	return func(vo *verifyOptions) {
		vo.searchDepth = depth
	}
}

func checkVerifyOpts(vo *verifyOptions) error {
	if vo.verifiedSource == nil {
		return ErrInvalidOption{
			Option: "verified source",
			Reason: "a verified attestation source is required",
		}
	}

	if len(vo.subjectDigests) == 0 {
		return ErrInvalidOption{
			Option: "subject digests",
			Reason: "at least one subject digest is required",
		}
	}

	if vo.searchDepth < 1 {
		return ErrInvalidOption{
			Option: "search depth",
			Reason: "search depth must be at least 1",
		}
	}

	return nil
}

type PolicyResult struct {
	Passed        bool
	ResultsByStep map[string]StepResult
}

func (p Policy) Verify(ctx context.Context, opts ...VerifyOption) (PolicyResult, error) {
	vo := &verifyOptions{
		searchDepth: 3,
	}

	for _, opt := range opts {
		opt(vo)
	}

	if err := checkVerifyOpts(vo); err != nil {
		return PolicyResult{}, err
	}

	if time.Now().After(p.Expires.Time) {
		return PolicyResult{}, ErrPolicyExpired(p.Expires.Time)
	}

	trustBundles, err := p.TrustBundles()
	if err != nil {
		return PolicyResult{}, err
	}

	attestationsByStep := make(map[string][]string)
	for name, step := range p.Steps {
		for _, attestation := range step.Attestations {
			attestationsByStep[name] = append(attestationsByStep[name], attestation.Type)
		}
	}

	resultsByStep := make(map[string]StepResult)
	for depth := 0; depth < vo.searchDepth; depth++ {
		for stepName, step := range p.Steps {
			statements, err := vo.verifiedSource.Search(ctx, stepName, vo.subjectDigests, attestationsByStep[stepName])
			if err != nil {
				return PolicyResult{}, err
			}

			stepResults := step.checkFunctionaries(statements, trustBundles)
			stepResults = step.validateAttestations(stepResults)

			// go through our new pass results and add any found backrefs to our search digests
			for _, coll := range stepResults.Passed {
				for _, digestSet := range coll.Collection.BackRefs() {
					vo.subjectDigests = append(vo.subjectDigests, digestSet)
				}
			}

			// merge the existing passed results with our new ones
			oldResults := resultsByStep[stepName]
			oldResults.Passed = append(oldResults.Passed, stepResults.Passed...)
			oldResults.Rejected = append(oldResults.Rejected, stepResults.Rejected...)
			resultsByStep[stepName] = oldResults
		}

		if _, err := p.verifyArtifacts(resultsByStep); err == nil {
			return PolicyResult{ResultsByStep: resultsByStep, Passed: true}, nil
		}
	}

	// mark all currently marked passed results as failed
	for step, results := range resultsByStep {
		modifiedResults := results
		for _, passed := range results.Passed {
			modifiedResults.Rejected = append(modifiedResults.Rejected, RejectedCollection{
				Collection: passed,
				Reason:     err,
			})
		}

		modifiedResults.Passed = nil
		resultsByStep[step] = modifiedResults
	}

	return PolicyResult{Passed: false, ResultsByStep: resultsByStep}, ErrPolicyDenied{Reasons: []string{"failed to find set of attestations that satisfies the policy"}}
}

// checkFunctionaries checks to make sure the signature on each statement corresponds to a trusted functionary for
// the step the statement corresponds to
func (step Step) checkFunctionaries(verifiedStatements []source.VerifiedCollection, trustBundles map[string]TrustBundle) StepResult {
	stepResult := StepResult{
		Step: step.Name,
	}

	for _, verifiedStatement := range verifiedStatements {
		if verifiedStatement.Statement.PredicateType != attestation.CollectionType {
			stepResult.Rejected = append(stepResult.Rejected, RejectedCollection{
				Collection: verifiedStatement,
				Reason:     fmt.Errorf("unrecognized predicate: %v", verifiedStatement.Statement.PredicateType),
			})

			log.Debugf("(policy) skipping statement: predicate type is not a collection (%v)", verifiedStatement.Statement.PredicateType)
			continue
		}

		for _, verifier := range verifiedStatement.Verifiers {
			verifierID, err := verifier.KeyID()
			if err != nil {
				log.Debugf("(policy) skipping verifier: could not get key id: %v", err)
				continue
			}

			passedFunctionary := false
			for _, functionary := range step.Functionaries {
				if functionary.PublicKeyID != "" && functionary.PublicKeyID == verifierID {
					passedFunctionary = true
					break
				}

				x509Verifier, ok := verifier.(*cryptoutil.X509Verifier)
				if !ok {
					log.Debugf("(policy) skipping verifier: verifier with ID %v is not a public key verifier or a x509 verifier", verifierID)
					continue
				}

				if len(functionary.CertConstraint.Roots) == 0 {
					log.Debugf("(policy) skipping verifier: verifier with ID %v is an x509 verifier, but step %v does not have any truested roots", verifierID, step)
					continue
				}

				if err := functionary.CertConstraint.Check(x509Verifier, trustBundles); err != nil {
					log.Debugf("(policy) skipping verifier: verifier with ID %v doesn't meet certificate constraint: %w", verifierID, err)
					continue
				} else {
					passedFunctionary = true
				}
			}

			if passedFunctionary {
				stepResult.Passed = append(stepResult.Passed, verifiedStatement)
			} else {
				stepResult.Rejected = append(stepResult.Rejected, RejectedCollection{
					Collection: verifiedStatement,
					Reason:     fmt.Errorf("no signature from allowed functionary"),
				})
			}
		}
	}

	return stepResult
}

// verifyArtifacts will check the artifacts (materials+products) of the step referred to by `ArtifactsFrom` against the
// materials of the original step.  This ensures file integrity between each step.
func (p Policy) verifyArtifacts(collectionsByStep map[string]StepResult) (map[string]StepResult, error) {
	for _, step := range p.Steps {
		newResultsByStep := collectionsByStep[step.Name]
		newResultsByStep.Passed = make([]source.VerifiedCollection, 0)
		for _, collection := range collectionsByStep[step.Name].Passed {
			if err := verifyCollectionArtifacts(step, collection, collectionsByStep); err == nil {
				newResultsByStep.Passed = append(newResultsByStep.Passed, collection)
			} else {
				newResultsByStep.Rejected = append(newResultsByStep.Rejected, RejectedCollection{
					Collection: collection,
					Reason:     err,
				})
			}
		}

		collectionsByStep[step.Name] = newResultsByStep
		if len(newResultsByStep.Passed) <= 0 {
			return nil, ErrNoAttestations(step.Name)
		}
	}

	return collectionsByStep, nil
}

func verifyCollectionArtifacts(step Step, collection source.VerifiedCollection, resultsByStep map[string]StepResult) error {
	mats := collection.Collection.Materials()
	for _, artifactsFrom := range step.ArtifactsFrom {
		accepted := make([]source.VerifiedCollection, 0)
		for _, testCollection := range resultsByStep[artifactsFrom].Passed {
			if err := compareArtifacts(mats, testCollection.Collection.Artifacts()); err != nil {
				break
			}

			accepted = append(accepted, testCollection)
		}

		if len(accepted) <= 0 {
			return ErrNoAttestations(step.Name)
		}
	}

	return nil
}

func compareArtifacts(mats map[string]cryptoutil.DigestSet, arts map[string]cryptoutil.DigestSet) error {
	for path, mat := range mats {
		art, ok := arts[path]
		if !ok {
			continue
		}

		if !mat.Equal(art) {
			return ErrMismatchArtifact{
				Artifact: art,
				Material: mat,
				Path:     path,
			}
		}
	}

	return nil
}
