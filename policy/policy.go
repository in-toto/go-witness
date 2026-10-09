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
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
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

// PublicKeyVerifiers returns verifiers for each of the policy's embedded public keys grouped by the key's ID
func (p Policy) PublicKeyVerifiers(ko map[string][]func(signer.SignerProvider) (signer.SignerProvider, error)) (map[string]cryptoutil.Verifier, error) {
	verifiers := make(map[string]cryptoutil.Verifier)
	var err error

	for _, key := range p.PublicKeys {
		var verifier cryptoutil.Verifier
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

			}
		}

		if verifier == nil {
			verifier, err = cryptoutil.NewVerifierFromReader(bytes.NewReader(key.Key))
			if err != nil {
				return nil, err
			}
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

			// We perform many searches against the same step (once per search-depth iteration), so we
			// merge the results. A single distinct collection can match on more than one iteration,
			// so de-duplicate by content identity to avoid counting it multiple times in Passed,
			// which would otherwise inflate any quorum/coverage decision a consumer makes.
			merged := resultsByStep[stepName]
			merged.Step = stepName
			merged.Passed = appendUniqueCollections(merged.Passed, stepResult.Passed)
			merged.Rejected = appendUniqueRejected(merged.Rejected, stepResult.Rejected)
			resultsByStep[stepName] = merged

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

	// A policy that defines no steps imposes no requirements and therefore proves nothing; treat it
	// as a verification failure rather than a vacuous pass.
	pass := len(p.Steps) > 0
	for _, result := range resultsByStep {
		stepPass := result.Analyze()
		if !stepPass {
			pass = false
		}
	}

	return pass, resultsByStep, nil
}

// collectionIdentity derives a content-based identity for a verified collection so the same
// distinct attestation is recognized across search-depth iterations. It is keyed on the statement
// content and the verified signer key IDs rather than the envelope reference, because a reference
// (for example MemorySource's) is only unique within a single source: a MultiSource composed of
// independent sources can legitimately return distinct envelopes that share a source-local
// reference, and those must not be collapsed. Identical statement content accepted under different
// functionaries remains distinct because the verified signer key IDs are part of the identity.
func collectionIdentity(c source.CollectionVerificationResult) string {
	h := sha256.New()

	// Length-prefix every field before hashing so the statement bytes and the signer key IDs are
	// unambiguously framed. Without a delimiter, a concatenation such as statement||signer could in
	// principle be reproduced by a different (statement, signer-set) pair and collapse two distinct
	// collections; explicit framing removes that ambiguity.
	writeField := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}

	stmt, err := json.Marshal(c.Statement)
	if err != nil {
		// A verified statement should always marshal; if it somehow does not, do not silently
		// collapse this collection with others by contributing nothing. Fold the error into the
		// identity so an unmarshalable statement stays distinct.
		stmt = []byte("collectionIdentity: unmarshalable statement: " + err.Error())
	}
	writeField(stmt)

	// Key on the verified signer identities, not the raw envelope signature list. DSSE signatures
	// cover only the payload, so unverified signature entries can be appended without invalidating
	// the attestation; keying on those would let a duplicate evade de-duplication by changing its
	// identity. The accepted functionaries' key IDs are trusted and stable across re-signing (unlike
	// randomized signature bytes). Sort so ordering does not affect the identity.
	signerSet := make(map[string]struct{}, len(c.ValidFunctionaries))
	for _, v := range c.ValidFunctionaries {
		kid, err := v.KeyID()
		if err != nil {
			continue
		}
		signerSet[kid] = struct{}{}
	}
	signers := make([]string, 0, len(signerSet))
	for kid := range signerSet {
		signers = append(signers, kid)
	}
	sort.Strings(signers)
	for _, s := range signers {
		writeField([]byte(s))
	}

	return hex.EncodeToString(h.Sum(nil))
}

// appendUniqueCollections appends additions to existing, skipping any collection whose content
// identity has already been seen.
func appendUniqueCollections(existing, additions []source.CollectionVerificationResult) []source.CollectionVerificationResult {
	seen := make(map[string]struct{}, len(existing))
	for _, c := range existing {
		seen[collectionIdentity(c)] = struct{}{}
	}

	for _, c := range additions {
		id := collectionIdentity(c)
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		existing = append(existing, c)
	}

	return existing
}

// appendUniqueRejected appends rejected collections, collapsing only entries that repeat the same
// collection AND the same rejection reason across search-depth iterations. The reason is part of the
// key so a collection that fails several distinct checks keeps every cause for diagnostics.
func appendUniqueRejected(existing, additions []RejectedCollection) []RejectedCollection {
	key := func(c RejectedCollection) string {
		reason := ""
		if c.Reason != nil {
			reason = c.Reason.Error()
		}
		return collectionIdentity(c.Collection) + "\x00" + reason
	}

	seen := make(map[string]struct{}, len(existing))
	for _, c := range existing {
		seen[key(c)] = struct{}{}
	}

	for _, c := range additions {
		k := key(c)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		existing = append(existing, c)
	}

	return existing
}

// checkFunctionaries checks to make sure the signature on each statement corresponds to a trusted functionary for
// the step the statement corresponds to
func (step Step) checkFunctionaries(statements []source.CollectionVerificationResult, trustBundles map[string]TrustBundle) StepResult {
	result := StepResult{Step: step.Name}
	for i, statement := range statements {
		// Check that the statement contains a predicate type that we accept
		if statement.Statement.PredicateType != attestation.CollectionType {
			result.Rejected = append(result.Rejected, RejectedCollection{Collection: statement, Reason: fmt.Errorf("predicate type %v is not a collection predicate type", statement.Statement.PredicateType)})
			continue
		}

		if len(statement.Verifiers) > 0 {
			for _, verifier := range statement.Verifiers {
				for _, functionary := range step.Functionaries {
					if err := functionary.Validate(verifier, trustBundles); err != nil {
						// Append to statements[i], not the range-copy `statement`: reading from the
						// copy (which is never updated in this loop) discards every prior entry, so a
						// collection with multiple valid functionaries would retain only the last one.
						statements[i].Warnings = append(statements[i].Warnings, fmt.Sprintf("failed to validate functionary of KeyID %s in step %s: %s", functionary.PublicKeyID, step.Name, err.Error()))
						continue
					} else {
						statements[i].ValidFunctionaries = append(statements[i].ValidFunctionaries, verifier)
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
		for i := range resultsByStep[step.Name].Passed {
			if err := verifyCollectionArtifacts(step, &resultsByStep[step.Name].Passed[i], resultsByStep); err == nil {
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

func verifyCollectionArtifacts(step Step, collection *source.CollectionVerificationResult, collectionsByStep map[string]StepResult) error {
	mats := collection.Collection.Materials()
	for _, artifactsFrom := range step.ArtifactsFrom {
		reasons := []string{}
		seenReasons := map[string]struct{}{}
		// The edge is satisfied if at least one passed upstream collection genuinely shares an
		// artifact with this step's materials and every shared digest matches. A candidate that has
		// no overlap or a mismatching digest is not the source, so skip it and keep looking rather
		// than terminating on the first non-match. Reasons are de-duplicated so searching multiple
		// candidates does not repeat the same failure.
		accepted := make([]source.CollectionVerificationResult, 0, 1)
		for _, testCollection := range collectionsByStep[artifactsFrom].Passed {
			if err := compareArtifacts(mats, testCollection.Collection.Artifacts()); err != nil {
				if _, ok := seenReasons[err.Error()]; !ok {
					seenReasons[err.Error()] = struct{}{}
					reasons = append(reasons, err.Error())
					collection.Warnings = append(collection.Warnings, fmt.Sprintf("failed to verify artifacts for step %s: %v", step.Name, err))
				}
				continue
			}

			accepted = append(accepted, testCollection)
			break
		}

		if len(accepted) == 0 {
			return ErrVerifyArtifactsFailed{Reasons: reasons}
		}
	}

	return nil
}

func compareArtifacts(mats map[string]cryptoutil.DigestSet, arts map[string]cryptoutil.DigestSet) error {
	overlap := 0
	for path, mat := range mats {
		art, ok := arts[path]
		if !ok {
			continue
		}

		overlap++
		if !mat.Equal(art) {
			return ErrMismatchArtifact{
				Artifact: art,
				Material: mat,
				Path:     path,
			}
		}
	}

	// An artifactsFrom edge means the downstream materials came from the upstream artifacts. If the
	// two share no path at all, nothing actually flowed between the steps and the comparison would
	// otherwise pass vacuously, so reject it.
	if overlap == 0 {
		return ErrNoArtifactOverlap{}
	}

	return nil
}
