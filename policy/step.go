// Copyright 2022 The Witness Contributors
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
	"fmt"
	"strings"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/source"
)

// +kubebuilder:object:generate=true
type Step struct {
	Name             string        `json:"name"`
	Functionaries    []Functionary `json:"functionaries"`
	Attestations     []Attestation `json:"attestations"`
	ArtifactsFrom    []string      `json:"artifactsFrom,omitempty"`
	AttestationsFrom []string      `json:"attestationsFrom,omitempty"`
}

// +kubebuilder:object:generate=true
type Functionary struct {
	Type           string         `json:"type"`
	CertConstraint CertConstraint `json:"certConstraint,omitempty"`
	PublicKeyID    string         `json:"publickeyid,omitempty"`
}

// +kubebuilder:object:generate=true
type Attestation struct {
	Type         string       `json:"type"`
	RegoPolicies []RegoPolicy `json:"regopolicies"`
}

// +kubebuilder:object:generate=true
type RegoPolicy struct {
	Module []byte `json:"module"`
	Name   string `json:"name"`
}

// StepResult contains information about the verified collections for each step.
// Passed contains the collections that passed any rego policies and all expected attestations exist.
// Rejected contains the rejected collections and the error that caused them to be rejected.
type StepResult struct {
	Step     string
	Passed   []source.CollectionVerificationResult
	Rejected []RejectedCollection
}

// Analyze inspects the StepResult to determine if the step passed or failed.
// We do this rather than failing at the first point of failure in the verification flow
// in order to save the failure reasons so we can present them all at the end of the verification process.
func (r StepResult) Analyze() bool {
	var pass bool
	if len(r.Passed) > 0 {
		pass = true
	}

	for _, coll := range r.Passed {
		// we don't fail on warnings so we process these under debug logs
		if len(coll.Warnings) > 0 {
			for _, warn := range coll.Warnings {
				log.Debug("Warning: Step: %s, Collection: %s, Warning: %s", r.Step, coll.Collection.Name, warn)
			}
		}

		// Want to ensure that undiscovered errors aren't lurking in the passed collections
		if len(coll.Errors) > 0 {
			for _, err := range coll.Errors {
				pass = false
				log.Errorf("Unexpected Error in Passed Collection: Step: %s, Collection: %s, Error: %s", r.Step, coll.Collection.Name, err)
			}
		}
	}

	return pass
}

func (r StepResult) HasErrors() bool {
	return len(r.Rejected) > 0
}

func (r StepResult) HasPassed() bool {
	return len(r.Passed) > 0
}

func (r StepResult) Error() string {
	errs := make([]string, len(r.Rejected))
	for i, reject := range r.Rejected {
		errs[i] = reject.Reason.Error()
	}

	return fmt.Sprintf("attestations for step %v could not be used due to:\n%v", r.Step, strings.Join(errs, "\n"))
}

type RejectedCollection struct {
	Collection source.CollectionVerificationResult
	Reason     error
}

func (f Functionary) Validate(verifier cryptoutil.Verifier, trustBundles map[string]TrustBundle) error {
	verifierID, err := verifier.KeyID()
	if err != nil {
		return fmt.Errorf("could not get key id: %w", err)
	}

	if f.PublicKeyID != "" && f.PublicKeyID == verifierID {
		return nil
	}

	x509Verifier, ok := verifier.(*cryptoutil.X509Verifier)
	if !ok {
		return fmt.Errorf("verifier with ID %v is not a public key verifier or a x509 verifier", verifierID)
	}

	if len(f.CertConstraint.Roots) == 0 {
		return fmt.Errorf("verifier with ID %v is an x509 verifier, but no trusted roots provided in functionary", verifierID)
	}

	if err := f.CertConstraint.Check(x509Verifier, trustBundles); err != nil {
		return fmt.Errorf("verifier with ID %v doesn't meet certificate constraint: %w", verifierID, err)
	}

	return nil
}

// validateAttestations will test each collection against to ensure the expected attestations
// appear in the collection as well as that any rego policies pass for the step.
// stepContext contains data from dependent steps (via AttestationsFrom) for cross-step validation.
func (s Step) validateAttestations(collectionResults []source.CollectionVerificationResult, stepContext map[string]interface{}) StepResult {
	result := StepResult{Step: s.Name}
	if len(collectionResults) <= 0 {
		return result
	}

	for _, collection := range collectionResults {
		if collection.Collection.Name != s.Name && collection.Collection.Name != "" {
			log.Debugf("Skipping collection %s as it is not for step %s", collection.Collection.Name, s.Name)
			continue
		}

		found := make(map[string]attestation.Attestor)
		reasons := make([]string, 0)
		passed := true
		if len(collection.Errors) > 0 {
			passed = false
			for _, err := range collection.Errors {
				reasons = append(reasons, fmt.Sprintf("collection verification failed: %s", err.Error()))
			}
		}

		for _, attestation := range collection.Collection.Attestations {
			found[attestation.Type] = attestation.Attestation
		}

		for _, expected := range s.Attestations {
			attestor, ok := found[expected.Type]
			if !ok {
				passed = false
				reasons = append(reasons, ErrMissingAttestation{
					Step:        s.Name,
					Attestation: expected.Type,
				}.Error())
			}

			// Pass step context to Rego evaluation for cross-step data access
			if err := EvaluateRegoPolicy(attestor, expected.RegoPolicies, stepContext); err != nil {
				passed = false
				reasons = append(reasons, err.Error())
			}
		}

		if passed {
			result.Passed = append(result.Passed, collection)
		} else {
			r := strings.Join(reasons, ",\n - ")
			reason := fmt.Sprintf("collection validation failed:\n - %s", r)
			result.Rejected = append(result.Rejected, RejectedCollection{
				Collection: collection,
				Reason:     fmt.Errorf("%s", reason),
			})
		}
	}

	return result
}

// buildStepContext extracts attestation data from verified dependent steps
// and builds a context map for Rego policy evaluation.
// Only data from steps with at least one PASSED collection is included.
func buildStepContext(resultsByStep map[string]StepResult, dependencies []string) map[string]interface{} {
	steps := make(map[string]interface{})

	for _, depName := range dependencies {
		result, exists := resultsByStep[depName]
		if !exists || len(result.Passed) == 0 {
			// Dependency not verified - exclude from context
			continue
		}

		stepData := make(map[string]interface{})
		attestations := make(map[string]interface{})

		// Extract ALL attestations from PASSED collections
		for _, coll := range result.Passed {
			for _, att := range coll.Collection.Attestations {
				// Store ALL attestations keyed by their type URL for full access
				// This allows Rego to access any attestation type:
				// input.steps.build.attestations["https://witness.dev/attestations/lockfiles/v0.1"]
				attestations[att.Type] = att.Attestation

				// Also provide convenience access for common patterns using interface detection
				// This allows simpler Rego: input.steps.build.products["file"].digest.sha256
				if producer, ok := att.Attestation.(attestation.Producer); ok {
					stepData["products"] = producer
				}
				if materialer, ok := att.Attestation.(attestation.Materialer); ok {
					stepData["materials"] = materialer
				}
			}
		}

		// Add the full attestations map to step data
		if len(attestations) > 0 {
			stepData["attestations"] = attestations
		}

		steps[depName] = stepData
	}

	return steps
}

// checkDependencies verifies that all required dependencies have been verified
// (i.e., have at least one PASSED collection).
func (s Step) checkDependencies(results map[string]StepResult) error {
	for _, dep := range s.AttestationsFrom {
		result, exists := results[dep]
		if !exists || len(result.Passed) == 0 {
			return ErrDependencyNotVerified{Step: dep}
		}
	}
	return nil
}
