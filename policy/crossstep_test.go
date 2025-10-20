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
	"context"
	"crypto"
	"encoding/json"
	"testing"
	"time"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/intoto"
	"github.com/in-toto/go-witness/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBuildStepContext(t *testing.T) {
	tests := []struct {
		name          string
		resultsByStep map[string]StepResult
		dependencies  []string
		expectSteps   []string
		validate      func(t *testing.T, ctx map[string]interface{})
	}{
		{
			name: "single dependency with products",
			resultsByStep: map[string]StepResult{
				"build": {
					Step: "build",
					Passed: []source.CollectionVerificationResult{
						{
							CollectionEnvelope: source.CollectionEnvelope{
								Collection: attestation.Collection{
									Name: "build",
									Attestations: []attestation.CollectionAttestation{
										{
											Type: "dummy-prods",
											Attestation: DummyProducer{
												P: map[string]attestation.Product{
													"app": {
														Digest: cryptoutil.DigestSet{
															cryptoutil.DigestValue{Hash: crypto.SHA256}: "abc123",
														},
														MimeType: "application/octet-stream",
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
			},
			dependencies: []string{"build"},
			expectSteps:  []string{"build"},
			validate: func(t *testing.T, ctx map[string]interface{}) {
				require.Contains(t, ctx, "build")
				buildData := ctx["build"].(map[string]interface{})
				require.Contains(t, buildData, "products")
			},
		},
		{
			name: "single dependency with materials",
			resultsByStep: map[string]StepResult{
				"test": {
					Step: "test",
					Passed: []source.CollectionVerificationResult{
						{
							CollectionEnvelope: source.CollectionEnvelope{
								Collection: attestation.Collection{
									Name: "test",
									Attestations: []attestation.CollectionAttestation{
										{
											Type: "dummy-mats",
											Attestation: DummyMaterialer{
												M: map[string]cryptoutil.DigestSet{
													"app": {
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
			},
			dependencies: []string{"test"},
			expectSteps:  []string{"test"},
			validate: func(t *testing.T, ctx map[string]interface{}) {
				require.Contains(t, ctx, "test")
				testData := ctx["test"].(map[string]interface{})
				require.Contains(t, testData, "materials")
			},
		},
		{
			name: "multiple dependencies",
			resultsByStep: map[string]StepResult{
				"build": {
					Step: "build",
					Passed: []source.CollectionVerificationResult{
						{
							CollectionEnvelope: source.CollectionEnvelope{
								Collection: attestation.Collection{
									Name: "build",
									Attestations: []attestation.CollectionAttestation{
										{
											Type: "dummy-prods",
											Attestation: DummyProducer{
												P: map[string]attestation.Product{
													"app": {
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
				},
				"test": {
					Step: "test",
					Passed: []source.CollectionVerificationResult{
						{
							CollectionEnvelope: source.CollectionEnvelope{
								Collection: attestation.Collection{
									Name: "test",
									Attestations: []attestation.CollectionAttestation{
										{
											Type: "dummy-mats",
											Attestation: DummyMaterialer{
												M: map[string]cryptoutil.DigestSet{
													"app": {
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
			},
			dependencies: []string{"build", "test"},
			expectSteps:  []string{"build", "test"},
			validate: func(t *testing.T, ctx map[string]interface{}) {
				require.Contains(t, ctx, "build")
				require.Contains(t, ctx, "test")
			},
		},
		{
			name: "dependency not verified - excluded from context",
			resultsByStep: map[string]StepResult{
				"build": {
					Step: "build",
					// No Passed collections - only rejected
					Rejected: []RejectedCollection{
						{Reason: assert.AnError},
					},
				},
			},
			dependencies: []string{"build"},
			expectSteps:  []string{}, // build excluded because not verified
			validate: func(t *testing.T, ctx map[string]interface{}) {
				require.NotContains(t, ctx, "build", "unverified step should not be in context")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := buildStepContext(tt.resultsByStep, tt.dependencies)
			assert.Len(t, ctx, len(tt.expectSteps))
			if tt.validate != nil {
				tt.validate(t, ctx)
			}
		})
	}
}

func TestRegoWithCrossStepData(t *testing.T) {
	// Test Rego policy that accesses data from dependent step
	regoPolicy := []byte(`package test

deny[msg] {
	# Access current step's material hash
	package_material := input.attestation.M["app"]["sha256"]

	# Access build step's product hash from context
	build_product := input.steps.build.products.P["app"].digest["sha256"]

	# Validate chain
	package_material != build_product
	msg := "artifact chain broken - app was tampered between build and package"
}`)

	tests := []struct {
		name         string
		attestor     attestation.Attestor
		stepContext  map[string]interface{}
		expectError  bool
		errorMessage string
	}{
		{
			name: "matching hashes - policy passes",
			attestor: DummyMaterialer{
				M: map[string]cryptoutil.DigestSet{
					"app": {
						cryptoutil.DigestValue{Hash: crypto.SHA256}: "abc123",
					},
				},
			},
			stepContext: map[string]interface{}{
				"build": map[string]interface{}{
					"products": DummyProducer{
						P: map[string]attestation.Product{
							"app": {
								Digest: cryptoutil.DigestSet{
									cryptoutil.DigestValue{Hash: crypto.SHA256}: "abc123",
								},
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "mismatched hashes - policy denies",
			attestor: DummyMaterialer{
				M: map[string]cryptoutil.DigestSet{
					"app": {
						cryptoutil.DigestValue{Hash: crypto.SHA256}: "different_hash",
					},
				},
			},
			stepContext: map[string]interface{}{
				"build": map[string]interface{}{
					"products": DummyProducer{
						P: map[string]attestation.Product{
							"app": {
								Digest: cryptoutil.DigestSet{
									cryptoutil.DigestValue{Hash: crypto.SHA256}: "abc123",
								},
							},
						},
					},
				},
			},
			expectError:  true,
			errorMessage: "artifact chain broken",
		},
		{
			name: "no cross-step data - policy passes with empty context",
			attestor: DummyMaterialer{
				M: map[string]cryptoutil.DigestSet{
					"app": {
						cryptoutil.DigestValue{Hash: crypto.SHA256}: "abc123",
					},
				},
			},
			stepContext: map[string]interface{}{}, // Empty context - backward compatibility
			expectError: false,                    // Policy should not fail on missing steps data
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policies := []RegoPolicy{
				{
					Name:   "chain-validation",
					Module: regoPolicy,
				},
			}

			err := EvaluateRegoPolicy(tt.attestor, policies, tt.stepContext)
			if tt.expectError {
				require.Error(t, err)
				if tt.errorMessage != "" {
					assert.Contains(t, err.Error(), tt.errorMessage)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCheckDependencies(t *testing.T) {
	tests := []struct {
		name          string
		dependencies  []string
		resultsByStep map[string]StepResult
		expectError   bool
	}{
		{
			name:         "all dependencies verified",
			dependencies: []string{"build", "test"},
			resultsByStep: map[string]StepResult{
				"build": {
					Step: "build",
					Passed: []source.CollectionVerificationResult{
						{}, // At least one passed collection
					},
				},
				"test": {
					Step: "test",
					Passed: []source.CollectionVerificationResult{
						{},
					},
				},
			},
			expectError: false,
		},
		{
			name:         "dependency not in results",
			dependencies: []string{"build"},
			resultsByStep: map[string]StepResult{
				"test": {Step: "test"},
			},
			expectError: true,
		},
		{
			name:         "dependency has no passed collections",
			dependencies: []string{"build"},
			resultsByStep: map[string]StepResult{
				"build": {
					Step:   "build",
					Passed: []source.CollectionVerificationResult{}, // Empty - failed
				},
			},
			expectError: true,
		},
		{
			name:          "no dependencies - always passes",
			dependencies:  []string{},
			resultsByStep: map[string]StepResult{},
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a step with the dependencies to test
			step := Step{AttestationsFrom: tt.dependencies}
			err := step.checkDependencies(tt.resultsByStep)
			if tt.expectError {
				assert.Error(t, err)
				assert.IsType(t, ErrDependencyNotVerified{}, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIntegrationArtifactChaining(t *testing.T) {
	// Integration test: Build produces artifact, Package consumes it
	// Package policy validates the artifact chain using cross-step data

	_, verifier, pubKeyPem, err := createTestKey()
	require.NoError(t, err)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)

	// Rego policy for package step that validates artifact chain
	chainPolicy := []byte(`package material

deny[msg] {
	# Get the package step's material hash (from DummyMaterialer)
	package_material := input.attestation.M["app"]["sha256"]

	# Get the build step's product hash (from DummyProducer in context)
	build_product := input.steps.build.products.P["app"].digest["sha256"]

	# They must match
	package_material != build_product
	msg := "artifact chain validation failed: build output doesn't match package input"
}`)

	functionary := Functionary{
		Type:        "PublicKey",
		PublicKeyID: keyID,
	}

	policy := Policy{
		Expires: metav1.NewTime(time.Now().Add(1 * time.Hour)),
		PublicKeys: map[string]PublicKey{
			keyID: {
				KeyID: keyID,
				Key:   pubKeyPem,
			},
		},
		Steps: map[string]Step{
			"build": {
				Name:          "build",
				Functionaries: []Functionary{functionary},
				Attestations: []Attestation{
					{Type: "dummy-prods"},
				},
			},
			"package": {
				Name:             "package",
				AttestationsFrom: []string{"build"}, // Package depends on build
				Functionaries:    []Functionary{functionary},
				Attestations: []Attestation{
					{
						Type: "dummy-mats",
						RegoPolicies: []RegoPolicy{
							{
								Name:   "chain-validation",
								Module: chainPolicy,
							},
						},
					},
				},
			},
		},
	}

	// Validate policy has no cycles
	err = policy.Validate()
	require.NoError(t, err, "policy should have no circular dependencies")

	// Test case 1: Matching hashes - should pass
	t.Run("matching hashes", func(t *testing.T) {
		matchingHash := "abc123def456"
		dummySha := matchingHash

		// Build step produces app
		buildProducts := map[string]attestation.Product{
			"app": {
				Digest: cryptoutil.DigestSet{
					cryptoutil.DigestValue{Hash: crypto.SHA256}: matchingHash,
				},
				MimeType: "application/octet-stream",
			},
		}

		// Package step consumes app with same hash
		packageMaterials := map[string]cryptoutil.DigestSet{
			"app": {
				cryptoutil.DigestValue{Hash: crypto.SHA256}: matchingHash,
			},
		}

		buildCollection := attestation.NewCollection("build", []attestation.CompletedAttestor{
			{
				Attestor:  DummyProducer{P: buildProducts},
				StartTime: time.Now().Add(-1 * time.Minute),
				EndTime:   time.Now(),
			},
		})

		packageCollection := attestation.NewCollection("package", []attestation.CompletedAttestor{
			{
				Attestor:  DummyMaterialer{M: packageMaterials},
				StartTime: time.Now().Add(-1 * time.Minute),
				EndTime:   time.Now(),
			},
		})

		buildJson, err := json.Marshal(buildCollection)
		require.NoError(t, err)
		packageJson, err := json.Marshal(packageCollection)
		require.NoError(t, err)

		buildStatement, err := intoto.NewStatement(attestation.CollectionType, buildJson, map[string]cryptoutil.DigestSet{})
		require.NoError(t, err)
		packageStatement, err := intoto.NewStatement(attestation.CollectionType, packageJson, map[string]cryptoutil.DigestSet{})
		require.NoError(t, err)

		pass, results, err := policy.Verify(
			context.Background(),
			WithSubjectDigests([]string{dummySha}),
			WithVerifiedSource(newDummyVerifiedSourcer([]source.CollectionVerificationResult{
				{
					Verifiers: []cryptoutil.Verifier{verifier},
					CollectionEnvelope: source.CollectionEnvelope{
						Statement:  buildStatement,
						Collection: buildCollection,
						Reference:  "build-ref",
					},
				},
				{
					Verifiers: []cryptoutil.Verifier{verifier},
					CollectionEnvelope: source.CollectionEnvelope{
						Statement:  packageStatement,
						Collection: packageCollection,
						Reference:  "package-ref",
					},
				},
			})),
		)

		require.NoError(t, err)
		assert.True(t, pass, "verification should pass with matching hashes")

		// Both steps should have passed collections
		assert.True(t, results["build"].HasPassed())
		assert.True(t, results["package"].HasPassed())
	})

	// Test case 2: Mismatched hashes - should fail
	t.Run("mismatched hashes", func(t *testing.T) {
		buildHash := "abc123def456"
		tamperedHash := "TAMPERED_HASH"
		dummySha := buildHash

		buildProducts := map[string]attestation.Product{
			"app": {
				Digest: cryptoutil.DigestSet{
					cryptoutil.DigestValue{Hash: crypto.SHA256}: buildHash,
				},
			},
		}

		// Package has DIFFERENT hash - artifact was tampered!
		packageMaterials := map[string]cryptoutil.DigestSet{
			"app": {
				cryptoutil.DigestValue{Hash: crypto.SHA256}: tamperedHash,
			},
		}

		buildCollection := attestation.NewCollection("build", []attestation.CompletedAttestor{
			{
				Attestor:  DummyProducer{P: buildProducts},
				StartTime: time.Now().Add(-1 * time.Minute),
				EndTime:   time.Now(),
			},
		})

		packageCollection := attestation.NewCollection("package", []attestation.CompletedAttestor{
			{
				Attestor:  DummyMaterialer{M: packageMaterials},
				StartTime: time.Now().Add(-1 * time.Minute),
				EndTime:   time.Now(),
			},
		})

		buildJson, err := json.Marshal(buildCollection)
		require.NoError(t, err)
		packageJson, err := json.Marshal(packageCollection)
		require.NoError(t, err)

		buildStatement, err := intoto.NewStatement(attestation.CollectionType, buildJson, map[string]cryptoutil.DigestSet{})
		require.NoError(t, err)
		packageStatement, err := intoto.NewStatement(attestation.CollectionType, packageJson, map[string]cryptoutil.DigestSet{})
		require.NoError(t, err)

		pass, results, err := policy.Verify(
			context.Background(),
			WithSubjectDigests([]string{dummySha}),
			WithVerifiedSource(newDummyVerifiedSourcer([]source.CollectionVerificationResult{
				{
					Verifiers: []cryptoutil.Verifier{verifier},
					CollectionEnvelope: source.CollectionEnvelope{
						Statement:  buildStatement,
						Collection: buildCollection,
						Reference:  "build-ref",
					},
				},
				{
					Verifiers: []cryptoutil.Verifier{verifier},
					CollectionEnvelope: source.CollectionEnvelope{
						Statement:  packageStatement,
						Collection: packageCollection,
						Reference:  "package-ref",
					},
				},
			})),
		)

		require.NoError(t, err)
		assert.False(t, pass, "verification should fail with mismatched hashes")

		// Build should pass, package should fail
		assert.True(t, results["build"].HasPassed())
		assert.False(t, results["package"].HasPassed())
		assert.True(t, results["package"].HasErrors())

		// Error should mention artifact chain validation
		assert.Contains(t, results["package"].Error(), "artifact chain validation failed")
	})
}
