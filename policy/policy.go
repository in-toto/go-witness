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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/signer"
	"github.com/in-toto/go-witness/signer/kms"
	"github.com/in-toto/go-witness/source"

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

// keyIDOverrideVerifier wraps a cryptoutil.Verifier to return a custom KeyID.
// This is used when an embedded key is provided for a KMS-style key ID, allowing
// the verifier to return the KMS URI instead of the computed hash of the public key.
type keyIDOverrideVerifier struct {
	cryptoutil.Verifier
	keyID string
}

func (v *keyIDOverrideVerifier) KeyID() (string, error) {
	return v.keyID, nil
}

// PublicKeyVerifiers returns verifiers for each of the policy's embedded public keys grouped by the key's ID.
// When a public key entry has both a KMS-style KeyID (e.g., awskms://...) AND an embedded key in the Key field,
// the embedded key is used directly for verification. This enables offline/air-gap verification scenarios
// where the KMS service may not be accessible. If no embedded key is provided, the KMS service is contacted.
func (p Policy) PublicKeyVerifiers(ko map[string][]func(signer.SignerProvider) (signer.SignerProvider, error)) (map[string]cryptoutil.Verifier, error) {
	verifiers := make(map[string]cryptoutil.Verifier)
	var err error

	for _, key := range p.PublicKeys {
		var verifier cryptoutil.Verifier

		// If an embedded key is provided, use it directly for verification.
		// This enables offline/air-gap verification even for KMS-style key IDs.
		if len(key.Key) > 0 {
			verifier, err = cryptoutil.NewVerifierFromReader(bytes.NewReader(key.Key))
			if err != nil {
				return nil, fmt.Errorf("failed to create verifier from embedded key: %w", err)
			}
		} else {
			// No embedded key - check if this is a KMS key ID and use KMS service
		for _, prefix := range kms.SupportedProviders() {
			if strings.HasPrefix(key.KeyID, prefix) {
				ksp := kms.New(kms.WithRef(key.KeyID), kms.WithHash("SHA256"))
				var vp signer.SignerProvider
				for _, opt := range ksp.Options {
					pn := opt.ProviderName()
					for _, setter := range ko[pn] {
						vp, err = setter(ksp)
						if err != nil {
							continue
						}
					}
				}

				if vp != nil {
					var ok bool
					ksp, ok = vp.(*kms.KMSSignerProvider)
					if !ok {
						return nil, fmt.Errorf("provided verifier provider is not a KMS verifier provider")
					}
				}

				verifier, err = ksp.Verifier(context.TODO())
				if err != nil {
					return nil, fmt.Errorf("failed to create kms verifier: %w", err)
				}
					break
				}
			}
		}

		// If still no verifier and no embedded key, this is an error
		if verifier == nil {
			return nil, fmt.Errorf("no embedded key provided for key ID %s and key ID is not a recognized KMS reference", key.KeyID)
		}

		keyID, err := verifier.KeyID()
		if err != nil {
			return nil, err
		}

		// For KMS key IDs with embedded keys, the computed keyID from the embedded key
		// will be a hash of the public key, not the KMS URI. We need to allow this mismatch
		// when an embedded key is provided with a KMS-style key ID.
		isKMSKeyID := false
		for _, prefix := range kms.SupportedProviders() {
			if strings.HasPrefix(key.KeyID, prefix) {
				isKMSKeyID = true
				break
			}
		}

		// Only check keyID match if:
		// 1. It's not a KMS key ID, OR
		// 2. It's a KMS key ID without an embedded key (verifier came from KMS)
		if !isKMSKeyID || len(key.Key) == 0 {
		if keyID != key.KeyID {
			return nil, ErrKeyIDMismatch{
				Expected: key.KeyID,
				Actual:   keyID,
			}
		}
		}

		// For KMS key IDs with embedded keys, wrap the verifier to return the KMS URI as its KeyID.
		// This ensures functionary matching works correctly since the policy's functionary
		// references the KMS URI, not the computed hash of the embedded public key.
		if isKMSKeyID && len(key.Key) > 0 {
			verifier = &keyIDOverrideVerifier{
				Verifier: verifier,
				keyID:    key.KeyID,
			}
		}

		// Use the policy's key ID as the map key (this preserves the KMS URI for functionary matching)
		verifiers[key.KeyID] = verifier
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
	subjectDigests []string
	searchDepth    int
}

func WithVerifiedSource(verifiedSource source.VerifiedSourcer) VerifyOption {
	return func(vo *verifyOptions) {
		vo.verifiedSource = verifiedSource
	}
}

func WithSubjectDigests(subjectDigests []string) VerifyOption {
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

func (p Policy) Verify(ctx context.Context, opts ...VerifyOption) (bool, map[string]StepResult, error) {
	vo := &verifyOptions{
		searchDepth: 3,
	}

	for _, opt := range opts {
		opt(vo)
	}

	if err := checkVerifyOpts(vo); err != nil {
		return false, nil, err
	}

	if time.Now().After(p.Expires.Time) {
		return false, nil, ErrPolicyExpired(p.Expires.Time)
	}

	trustBundles, err := p.TrustBundles()
	if err != nil {
		return false, nil, err
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
			// Use search to get all the attestations that match the supplied step name and subjects
			collections, err := vo.verifiedSource.Search(ctx, stepName, vo.subjectDigests, attestationsByStep[stepName])
			if err != nil {
				return false, nil, err
			}

			if len(collections) == 0 {
				collections = append(collections, source.CollectionVerificationResult{Errors: []error{ErrNoCollections{Step: stepName}}})
			}

			// Verify the functionaries
			functionaryCheckResults := step.checkFunctionaries(collections, trustBundles)
			stepResult := step.validateAttestations(functionaryCheckResults.Passed)
			stepResult.Rejected = append(stepResult.Rejected, functionaryCheckResults.Rejected...)

			// We perform many searches against the same step, so we need to merge the relevant fields
			if resultsByStep[stepName].Step == "" {
				resultsByStep[stepName] = stepResult
			} else {
				if result, ok := resultsByStep[stepName]; ok {
					result.Passed = append(result.Passed, stepResult.Passed...)
					result.Rejected = append(result.Rejected, stepResult.Rejected...)
					resultsByStep[stepName] = result
				}
			}

			for _, coll := range stepResult.Passed {
				for _, digestSet := range coll.Collection.BackRefs() {
					for _, digest := range digestSet {
						vo.subjectDigests = append(vo.subjectDigests, digest)
					}
				}
			}
		}
	}

	resultsByStep, err = p.verifyArtifacts(resultsByStep)
	if err != nil {
		return false, nil, fmt.Errorf("failed to verify artifacts: %w", err)
	}

	pass := true
	for _, result := range resultsByStep {
		p := result.Analyze()
		if !p {
			pass = false
		}
	}

	return pass, resultsByStep, nil
}

// checkFunctionaries checks to make sure the signature on each statement corresponds to a trusted functionary for
// the step the statement corresponds to
func (step Step) checkFunctionaries(statements []source.CollectionVerificationResult, trustBundles map[string]TrustBundle) StepResult {
	result := StepResult{Step: step.Name}
	for i, statement := range statements {
		// Check that the statement contains a predicate type that we accept
		if statement.Statement.PredicateType != attestation.CollectionType {
			result.Rejected = append(result.Rejected, RejectedCollection{Collection: statement, Reason: fmt.Errorf("predicate type %v is not a collection predicate type", statement.Statement.PredicateType)})
		}

		if len(statement.Verifiers) > 0 {
			for _, verifier := range statement.Verifiers {
				for _, functionary := range step.Functionaries {
					if err := functionary.Validate(verifier, trustBundles); err != nil {
						statements[i].Warnings = append(statement.Warnings, fmt.Sprintf("failed to validate functionary of KeyID %s in step %s: %s", functionary.PublicKeyID, step.Name, err.Error()))
						continue
					} else {
						statements[i].ValidFunctionaries = append(statement.ValidFunctionaries, verifier)
					}
				}
			}

			if len(statements[i].ValidFunctionaries) == 0 {
				result.Rejected = append(result.Rejected, RejectedCollection{Collection: statements[i], Reason: fmt.Errorf("no verifiers matched with allowed functionaries for step %s", step.Name)})
			} else {
				result.Passed = append(result.Passed, statements[i])
			}
		} else {
			result.Rejected = append(result.Rejected, RejectedCollection{Collection: statements[i], Reason: fmt.Errorf("no verifiers present to validate against collection verifiers")})
		}
	}

	return result
}

// verifyArtifacts will check the artifacts (materials+products) of the step referred to by `ArtifactsFrom` against the
// materials of the original step.  This ensures file integrity between each step.
func (p Policy) verifyArtifacts(resultsByStep map[string]StepResult) (map[string]StepResult, error) {
	for _, step := range p.Steps {
		accepted := false
		if len(resultsByStep[step.Name].Passed) == 0 {
			if result, ok := resultsByStep[step.Name]; ok {
				result.Rejected = append(result.Rejected, RejectedCollection{Reason: fmt.Errorf("failed to verify artifacts for step %s: no passed collections present", step.Name)})
				resultsByStep[step.Name] = result
			} else {
				return nil, fmt.Errorf("failed to find step %s in step results map", step.Name)
			}

			continue
		}

		reasons := []error{}
		for _, collection := range resultsByStep[step.Name].Passed {
			if err := verifyCollectionArtifacts(step, collection, resultsByStep); err == nil {
				accepted = true
			} else {
				reasons = append(reasons, err)
			}
		}

		if !accepted {
			// can't address the map fields directly so have to make a copy and overwrite
			if result, ok := resultsByStep[step.Name]; ok {
				reject := RejectedCollection{Reason: fmt.Errorf("failed to verify artifacts for step %s: ", step.Name)}
				for _, reason := range reasons {
					reject.Reason = errors.Join(reject.Reason, reason)
				}

				result.Rejected = append(result.Rejected, reject)
				result.Passed = []source.CollectionVerificationResult{}
				resultsByStep[step.Name] = result
			}
		}

	}

	return resultsByStep, nil
}

func verifyCollectionArtifacts(step Step, collection source.CollectionVerificationResult, collectionsByStep map[string]StepResult) error {
	mats := collection.Collection.Materials()
	reasons := []string{}
	for _, artifactsFrom := range step.ArtifactsFrom {
		accepted := make([]source.CollectionVerificationResult, 0)
		for _, testCollection := range collectionsByStep[artifactsFrom].Passed {
			if err := compareArtifacts(mats, testCollection.Collection.Artifacts()); err != nil {
				collection.Warnings = append(collection.Warnings, fmt.Sprintf("failed to verify artifacts for step %s: %v", step.Name, err))
				reasons = append(reasons, err.Error())
				break
			}

			accepted = append(accepted, testCollection)
		}

		if len(accepted) <= 0 {
			return ErrVerifyArtifactsFailed{Reasons: reasons}
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
