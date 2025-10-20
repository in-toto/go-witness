// Copyright 2025 The Witness Contributors
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
	"crypto"
	"testing"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/source"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestThreatModel_UnverifiedStepDataIsolation ensures that steps with no passed collections
// do not leak their attestation data to dependent steps
func TestThreatModel_UnverifiedStepDataIsolation(t *testing.T) {
	// Scenario: Attacker compromises build step but it fails verification
	// Test ensures the compromised data doesn't leak to test step

	buildResult := StepResult{
		Step: "build",
		// No Passed collections - all rejected due to signature failure
		Rejected: []RejectedCollection{
			{
				Collection: source.CollectionVerificationResult{
					CollectionEnvelope: source.CollectionEnvelope{
						Collection: attestation.Collection{
							Name: "build",
							Attestations: []attestation.CollectionAttestation{
								{
									Type: "https://witness.dev/attestations/product/v0.1",
									Attestation: DummyProducer{
										P: map[string]attestation.Product{
											"malicious.exe": {
												MimeType: "application/x-executable",
												Digest: cryptoutil.DigestSet{
													cryptoutil.DigestValue{Hash: crypto.SHA256}: "deadbeef", // Malicious artifact
												},
											},
										},
									},
								},
							},
						},
					},
				},
				Reason: nil,
			},
		},
	}

	testResult := StepResult{
		Step:   "test",
		Passed: []source.CollectionVerificationResult{}, // Test step passed but has no build data
	}

	resultsByStep := map[string]StepResult{
		"build": buildResult,
		"test":  testResult,
	}

	// Test step declares dependency on build
	stepContext := buildStepContext(resultsByStep, []string{"build"})

	// SECURITY REQUIREMENT: Unverified build step data MUST NOT be accessible
	assert.Empty(t, stepContext, "unverified step data must not be accessible to dependents")
}

// TestThreatModel_PartialVerificationDataIsolation ensures that when a step has both
// passed and rejected collections, only data from passed collections is accessible
func TestThreatModel_PartialVerificationDataIsolation(t *testing.T) {
	// Scenario: Build step has multiple attestations, some pass, some fail
	// Only passed attestation data should be accessible

	buildResult := StepResult{
		Step: "build",
		Passed: []source.CollectionVerificationResult{
			{
				CollectionEnvelope: source.CollectionEnvelope{
					Collection: attestation.Collection{
						Name: "build",
						Attestations: []attestation.CollectionAttestation{
							{
								Type: "https://witness.dev/attestations/product/v0.1",
								Attestation: DummyProducer{
									P: map[string]attestation.Product{
										"safe.exe": {
											MimeType: "application/x-executable",
											Digest: cryptoutil.DigestSet{
												cryptoutil.DigestValue{Hash: crypto.SHA256}: "cafebabe",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		Rejected: []RejectedCollection{
			{
				Collection: source.CollectionVerificationResult{
					CollectionEnvelope: source.CollectionEnvelope{
						Collection: attestation.Collection{
							Name: "build",
							Attestations: []attestation.CollectionAttestation{
								{
									Type: "https://witness.dev/attestations/product/v0.1",
									Attestation: DummyProducer{
										P: map[string]attestation.Product{
											"malicious.exe": {
												MimeType: "application/x-executable",
												Digest: cryptoutil.DigestSet{
													cryptoutil.DigestValue{Hash: crypto.SHA256}: "deadbeef",
												},
											},
										},
									},
								},
							},
						},
					},
				},
				Reason: nil,
			},
		},
	}

	resultsByStep := map[string]StepResult{
		"build": buildResult,
	}

	stepContext := buildStepContext(resultsByStep, []string{"build"})

	// SECURITY REQUIREMENT: Only passed collection data should be accessible
	require.NotEmpty(t, stepContext, "passed collection data should be accessible")
	buildData := stepContext["build"].(map[string]interface{})
	products := buildData["products"].(attestation.Producer)

	// Should have safe.exe from passed collection
	safeProducts := products.Products()
	assert.Contains(t, safeProducts, "safe.exe", "passed collection products should be accessible")

	// Should NOT have malicious.exe from rejected collection
	assert.NotContains(t, safeProducts, "malicious.exe", "rejected collection products must not be accessible")
}

// TestThreatModel_MissingDependencyPreventsExecution ensures that steps cannot be
// evaluated when their dependencies haven't been verified
func TestThreatModel_MissingDependencyPreventsExecution(t *testing.T) {
	// Scenario: Attacker tries to skip build step and go directly to test

	testStep := Step{
		Name:             "test",
		AttestationsFrom: []string{"build"}, // Declares dependency on build
		Attestations:     []Attestation{},
	}

	// resultsByStep has test but NOT build
	resultsByStep := map[string]StepResult{
		"test": {
			Step:   "test",
			Passed: []source.CollectionVerificationResult{},
		},
	}

	// SECURITY REQUIREMENT: checkDependencies must detect missing build step
	err := testStep.checkDependencies(resultsByStep)
	require.Error(t, err, "missing dependency must be detected")
	assert.IsType(t, ErrDependencyNotVerified{}, err, "error should be ErrDependencyNotVerified")
	assert.Contains(t, err.Error(), "build", "error should mention missing dependency")
}

// TestThreatModel_FailedDependencyPreventsExecution ensures that steps cannot be
// evaluated when their dependencies failed verification
func TestThreatModel_FailedDependencyPreventsExecution(t *testing.T) {
	// Scenario: Build step failed verification, test step should not execute

	testStep := Step{
		Name:             "test",
		AttestationsFrom: []string{"build"},
		Attestations:     []Attestation{},
	}

	// Build step exists but has no passed collections (failed)
	resultsByStep := map[string]StepResult{
		"build": {
			Step:   "build",
			Passed: []source.CollectionVerificationResult{}, // Empty - failed
			Rejected: []RejectedCollection{
				{Reason: nil}, // Has rejections
			},
		},
		"test": {
			Step:   "test",
			Passed: []source.CollectionVerificationResult{},
		},
	}

	// SECURITY REQUIREMENT: checkDependencies must detect failed build step
	err := testStep.checkDependencies(resultsByStep)
	require.Error(t, err, "failed dependency must be detected")
	assert.IsType(t, ErrDependencyNotVerified{}, err, "error should be ErrDependencyNotVerified")
	assert.Contains(t, err.Error(), "build", "error should mention failed dependency")
}

// TestThreatModel_CircularDependencyAttack ensures that circular dependencies
// are detected at policy load time before any verification happens
func TestThreatModel_CircularDependencyAttack(t *testing.T) {
	testCases := []struct {
		name        string
		policy      Policy
		shouldError bool
		description string
	}{
		{
			name: "direct cycle attack",
			policy: Policy{
				Steps: map[string]Step{
					"build": {
						Name:             "build",
						AttestationsFrom: []string{"test"},
					},
					"test": {
						Name:             "test",
						AttestationsFrom: []string{"build"},
					},
				},
			},
			shouldError: true,
			description: "attacker creates build→test→build cycle to confuse verification",
		},
		{
			name: "self-reference attack",
			policy: Policy{
				Steps: map[string]Step{
					"build": {
						Name:             "build",
						AttestationsFrom: []string{"build"}, // Self-reference
					},
				},
			},
			shouldError: true,
			description: "attacker creates self-referencing step (returns specific ErrSelfReference)",
		},
		{
			name: "indirect cycle attack",
			policy: Policy{
				Steps: map[string]Step{
					"build": {
						Name:             "build",
						AttestationsFrom: []string{"package"},
					},
					"test": {
						Name:             "test",
						AttestationsFrom: []string{"build"},
					},
					"package": {
						Name:             "package",
						AttestationsFrom: []string{"test"},
					},
				},
			},
			shouldError: true,
			description: "attacker creates build→package→test→build cycle",
		},
		{
			name: "valid DAG",
			policy: Policy{
				Steps: map[string]Step{
					"build": {
						Name:             "build",
						AttestationsFrom: []string{},
					},
					"test": {
						Name:             "test",
						AttestationsFrom: []string{"build"},
					},
					"package": {
						Name:             "package",
						AttestationsFrom: []string{"build", "test"},
					},
				},
			},
			shouldError: false,
			description: "valid dependency graph should be allowed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.policy.Validate()
			if tc.shouldError {
				require.Error(t, err, tc.description)
				// Verify it's a dependency-related error (ErrCircularDependency or ErrSelfReference)
				_, isCircular := err.(ErrCircularDependency)
				_, isSelfRef := err.(ErrSelfReference)
				assert.True(t, isCircular || isSelfRef,
					"should return circular dependency or self-reference error, got: %T", err)
			} else {
				require.NoError(t, err, tc.description)
			}
		})
	}
}

// TestThreatModel_DataIsolationBetweenSteps ensures that steps can only access
// data from explicitly declared dependencies, not from all verified steps
func TestThreatModel_DataIsolationBetweenSteps(t *testing.T) {
	// Scenario: Three steps (build, audit, test) all verified
	// Test declares dependency only on build, not audit
	// Test should NOT be able to access audit data

	buildResult := StepResult{
		Step: "build",
		Passed: []source.CollectionVerificationResult{
			{
				CollectionEnvelope: source.CollectionEnvelope{
					Collection: attestation.Collection{
						Name: "build",
						Attestations: []attestation.CollectionAttestation{
							{
								Type: "https://witness.dev/attestations/product/v0.1",
								Attestation: DummyProducer{
									P: map[string]attestation.Product{
										"app": {
											MimeType: "application/x-executable",
											Digest: cryptoutil.DigestSet{
												cryptoutil.DigestValue{Hash: crypto.SHA256}: "abc123",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	auditResult := StepResult{
		Step: "audit",
		Passed: []source.CollectionVerificationResult{
			{
				CollectionEnvelope: source.CollectionEnvelope{
					Collection: attestation.Collection{
						Name: "audit",
						Attestations: []attestation.CollectionAttestation{
							{
								Type: "https://witness.dev/attestations/product/v0.1",
								Attestation: DummyProducer{
									P: map[string]attestation.Product{
										"audit-report": {
											MimeType: "text/plain",
											Digest: cryptoutil.DigestSet{
												cryptoutil.DigestValue{Hash: crypto.SHA256}: "def456",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	resultsByStep := map[string]StepResult{
		"build": buildResult,
		"audit": auditResult,
	}

	// Test declares dependency ONLY on build, not audit
	stepContext := buildStepContext(resultsByStep, []string{"build"})

	// SECURITY REQUIREMENT: Only explicitly declared dependencies should be accessible
	assert.Contains(t, stepContext, "build", "declared dependency should be accessible")
	assert.NotContains(t, stepContext, "audit", "non-declared step should NOT be accessible")
}

// TestThreatModel_EmptyDependencyListIsSecure ensures that steps with no
// dependencies get no cross-step data
func TestThreatModel_EmptyDependencyListIsSecure(t *testing.T) {
	// Scenario: Build step has no dependencies, should get empty context

	buildResult := StepResult{
		Step: "build",
		Passed: []source.CollectionVerificationResult{
			{
				CollectionEnvelope: source.CollectionEnvelope{
					Collection: attestation.Collection{
						Name:         "build",
						Attestations: []attestation.CollectionAttestation{},
					},
				},
			},
		},
	}

	resultsByStep := map[string]StepResult{
		"build": buildResult,
	}

	// No dependencies declared
	stepContext := buildStepContext(resultsByStep, []string{})

	// SECURITY REQUIREMENT: Empty dependency list means no cross-step access
	assert.Empty(t, stepContext, "step with no dependencies should get empty context")
}

// TestThreatModel_NonExistentDependencyIsSecure ensures that declaring a
// dependency on a non-existent step doesn't cause panics or unexpected behavior
func TestThreatModel_NonExistentDependencyIsSecure(t *testing.T) {
	// Scenario: Test declares dependency on non-existent "phantom" step

	resultsByStep := map[string]StepResult{
		"test": {
			Step:   "test",
			Passed: []source.CollectionVerificationResult{},
		},
	}

	// Declare dependency on non-existent step
	stepContext := buildStepContext(resultsByStep, []string{"phantom"})

	// SECURITY REQUIREMENT: Non-existent dependencies result in empty context (safe failure)
	assert.Empty(t, stepContext, "non-existent dependency should result in empty context")
}

// TestThreatModel_CascadingFailure ensures that when a dependency fails,
// all dependent steps also fail verification
func TestThreatModel_CascadingFailure(t *testing.T) {
	// Scenario: build→test→package chain, build fails
	// Both test and package should fail due to cascade

	policy := Policy{
		Steps: map[string]Step{
			"build": {
				Name:             "build",
				AttestationsFrom: []string{},
			},
			"test": {
				Name:             "test",
				AttestationsFrom: []string{"build"},
			},
			"package": {
				Name:             "package",
				AttestationsFrom: []string{"test"},
			},
		},
	}

	// Build step failed
	resultsByStep := map[string]StepResult{
		"build": {
			Step:     "build",
			Passed:   []source.CollectionVerificationResult{}, // Failed
			Rejected: []RejectedCollection{{Reason: nil}},
		},
	}

	// Test step should fail when checking dependencies
	testStep := policy.Steps["test"]
	err := testStep.checkDependencies(resultsByStep)
	assert.Error(t, err, "test should fail when build fails")

	// Package step should also fail when checking dependencies
	// (even though its direct dependency is test, the cascade should prevent it)
	packageStep := policy.Steps["package"]
	err = packageStep.checkDependencies(resultsByStep)
	assert.Error(t, err, "package should fail when build fails (cascading)")
}

// TestThreatModel_TopologicalSortPreventsEarlyExecution ensures that
// topological sort prevents steps from being evaluated before their dependencies
func TestThreatModel_TopologicalSortPreventsEarlyExecution(t *testing.T) {
	// Scenario: Policy declares test→build→package (wrong order)
	// Topological sort should reorder to build→test→package

	policy := Policy{
		Steps: map[string]Step{
			"test": {
				Name:             "test",
				AttestationsFrom: []string{"build"},
			},
			"build": {
				Name:             "build",
				AttestationsFrom: []string{},
			},
			"package": {
				Name:             "package",
				AttestationsFrom: []string{"build", "test"},
			},
		},
	}

	sorted, err := policy.topologicalSort()
	require.NoError(t, err)

	// SECURITY REQUIREMENT: Dependencies must be evaluated before dependents
	buildIdx := -1
	testIdx := -1
	packageIdx := -1
	for i, step := range sorted {
		switch step {
		case "build":
			buildIdx = i
		case "test":
			testIdx = i
		case "package":
			packageIdx = i
		}
	}

	assert.True(t, buildIdx < testIdx, "build must come before test")
	assert.True(t, buildIdx < packageIdx, "build must come before package")
	assert.True(t, testIdx < packageIdx, "test must come before package")
}

// fakeProducer is an attestation that looks like a producer (has "product" in the type string)
// but doesn't actually implement the Producer interface. Used to test type spoofing attacks.
type fakeProducer struct{}

func (fakeProducer) Name() string {
	return "fake-product"
}

func (fakeProducer) Type() string {
	return "https://evil.com/attestations/product/v0.1"
}

func (fakeProducer) RunType() attestation.RunType {
	return attestation.PostProductRunType
}

func (fakeProducer) Attest(*attestation.AttestationContext) error {
	return nil
}

func (fakeProducer) Schema() *jsonschema.Schema {
	return nil
}

// TestThreatModel_InterfaceBasedDetectionPreventsTypeSpoofing ensures that
// attestation type detection uses interface assertions, not string matching,
// preventing type spoofing attacks
func TestThreatModel_InterfaceBasedDetectionPreventsTypeSpoofing(t *testing.T) {
	// Scenario: Attacker creates attestation with "product" in type string
	// but doesn't implement Producer interface

	resultsByStep := map[string]StepResult{
		"build": {
			Step: "build",
			Passed: []source.CollectionVerificationResult{
				{
					CollectionEnvelope: source.CollectionEnvelope{
						Collection: attestation.Collection{
							Name: "build",
							Attestations: []attestation.CollectionAttestation{
								{
									Type:        "https://evil.com/attestations/product/v0.1", // Suspicious type
									Attestation: fakeProducer{},                               // Doesn't implement Producer
								},
							},
						},
					},
				},
			},
		},
	}

	stepContext := buildStepContext(resultsByStep, []string{"build"})

	// SECURITY REQUIREMENT: Type string spoofing should not work
	buildData, ok := stepContext["build"].(map[string]interface{})
	require.True(t, ok, "build data should exist")

	// Since fakeProducer doesn't implement Producer interface,
	// products field should not exist
	_, hasProducts := buildData["products"]
	assert.False(t, hasProducts, "spoofed type should not be detected as producer")
}
