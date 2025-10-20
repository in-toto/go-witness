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
	"strings"
	"testing"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/source"
)

// FuzzPolicyValidate fuzzes the Policy.Validate() function to find edge cases
// in circular dependency detection
func FuzzPolicyValidate(f *testing.F) {
	// Seed corpus with known patterns
	f.Add("build", "test,package", "build", "") // Linear chain
	f.Add("build", "test", "test", "build")     // Direct cycle
	f.Add("build", "build", "", "")             // Self-reference
	f.Add("a", "b", "b", "c,a")                 // Indirect cycle
	f.Add("step1", "", "step2", "")             // Independent steps
	f.Add("", "", "", "")                       // Empty policy
	f.Add("step", ",,,,", "other", ",,,")       // Malformed deps

	f.Fuzz(func(t *testing.T, step1Name, step1Deps, step2Name, step2Deps string) {
		// Skip invalid inputs
		if step1Name == "" && step2Name == "" {
			t.Skip()
		}

		policy := Policy{
			Steps: make(map[string]Step),
		}

		// Build step 1
		if step1Name != "" {
			deps1 := []string{}
			if step1Deps != "" {
				deps1 = strings.Split(step1Deps, ",")
			}
			policy.Steps[step1Name] = Step{
				Name:             step1Name,
				AttestationsFrom: deps1,
			}
		}

		// Build step 2
		if step2Name != "" {
			deps2 := []string{}
			if step2Deps != "" {
				deps2 = strings.Split(step2Deps, ",")
			}
			policy.Steps[step2Name] = Step{
				Name:             step2Name,
				AttestationsFrom: deps2,
			}
		}

		// Validate should never panic, regardless of input
		_ = policy.Validate()
	})
}

// FuzzTopologicalSort fuzzes the topological sort algorithm to ensure
// it handles all dependency graph structures correctly
func FuzzTopologicalSort(f *testing.F) {
	// Seed corpus
	f.Add("a", "b,c", "b", "c", "c", "")  // Diamond
	f.Add("a", "b", "b", "c", "c", "d")   // Linear chain
	f.Add("a", "b", "b", "a", "c", "")    // Cycle
	f.Add("a", "", "b", "", "c", "")      // Independent
	f.Add("x", "y,z,w", "y", "", "z", "") // Multiple deps

	f.Fuzz(func(t *testing.T, name1, deps1, name2, deps2, name3, deps3 string) {
		// Skip invalid inputs
		if name1 == "" || name2 == "" || name3 == "" {
			t.Skip()
		}

		// Prevent duplicate names
		if name1 == name2 || name2 == name3 || name1 == name3 {
			t.Skip()
		}

		policy := Policy{
			Steps: map[string]Step{
				name1: {
					Name:             name1,
					AttestationsFrom: strings.Split(deps1, ","),
				},
				name2: {
					Name:             name2,
					AttestationsFrom: strings.Split(deps2, ","),
				},
				name3: {
					Name:             name3,
					AttestationsFrom: strings.Split(deps3, ","),
				},
			},
		}

		// topologicalSort should never panic
		sorted, err := policy.topologicalSort()

		// If no error, verify basic invariants
		if err == nil {
			// All steps should be in the result
			if len(sorted) != len(policy.Steps) {
				t.Errorf("topological sort returned %d steps, expected %d", len(sorted), len(policy.Steps))
			}

			// No duplicates
			seen := make(map[string]bool)
			for _, step := range sorted {
				if seen[step] {
					t.Errorf("duplicate step in sorted result: %s", step)
				}
				seen[step] = true
			}
		}
	})
}

// FuzzBuildStepContext fuzzes the buildStepContext function to ensure
// it handles all result combinations correctly
func FuzzBuildStepContext(f *testing.F) {
	// Seed corpus
	f.Add("build", true, "test", false, "build")     // Build passed, test failed
	f.Add("build", false, "test", true, "build")     // Build failed, test passed
	f.Add("build", true, "test", true, "build,test") // Both passed
	f.Add("step1", false, "step2", false, "")        // Both failed

	f.Fuzz(func(t *testing.T, step1Name string, step1Passed bool, step2Name string, step2Passed bool, deps string) {
		// Skip invalid inputs
		if step1Name == "" || step2Name == "" {
			t.Skip()
		}

		// Build result map
		resultsByStep := make(map[string]StepResult)

		// Add step1
		if step1Passed {
			resultsByStep[step1Name] = StepResult{
				Step: step1Name,
				Passed: []source.CollectionVerificationResult{
					{
						CollectionEnvelope: source.CollectionEnvelope{
							Collection: attestation.Collection{
								Name: step1Name,
								Attestations: []attestation.CollectionAttestation{
									{
										Type: "dummy",
										Attestation: DummyProducer{
											P: map[string]attestation.Product{
												"artifact": {
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
		} else {
			resultsByStep[step1Name] = StepResult{
				Step:   step1Name,
				Passed: []source.CollectionVerificationResult{},
			}
		}

		// Add step2
		if step2Passed {
			resultsByStep[step2Name] = StepResult{
				Step: step2Name,
				Passed: []source.CollectionVerificationResult{
					{
						CollectionEnvelope: source.CollectionEnvelope{
							Collection: attestation.Collection{
								Name: step2Name,
								Attestations: []attestation.CollectionAttestation{
									{
										Type: "dummy",
										Attestation: DummyProducer{
											P: map[string]attestation.Product{
												"artifact2": {
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
		} else {
			resultsByStep[step2Name] = StepResult{
				Step:   step2Name,
				Passed: []source.CollectionVerificationResult{},
			}
		}

		// Parse dependencies
		var dependencies []string
		if deps != "" {
			dependencies = strings.Split(deps, ",")
		}

		// buildStepContext should never panic
		ctx := buildStepContext(resultsByStep, dependencies)

		// Verify only passed steps with matching dependencies appear in context
		for _, dep := range dependencies {
			result, exists := resultsByStep[dep]
			if exists && len(result.Passed) > 0 {
				// Should be in context
				if _, ok := ctx[dep]; !ok {
					t.Errorf("passed dependency %s not in context", dep)
				}
			} else {
				// Should NOT be in context
				if _, ok := ctx[dep]; ok {
					t.Errorf("failed/missing dependency %s should not be in context", dep)
				}
			}
		}
	})
}

// FuzzCheckDependencies fuzzes the checkDependencies method to ensure
// it correctly validates dependency states
func FuzzCheckDependencies(f *testing.F) {
	// Seed corpus
	f.Add("build", true, "build")     // Valid dependency
	f.Add("build", false, "build")    // Failed dependency
	f.Add("missing", true, "missing") // Missing dependency
	f.Add("dep", true, "other")       // Different dependency

	f.Fuzz(func(t *testing.T, stepName string, hasPassed bool, depName string) {
		// Skip invalid inputs
		if stepName == "" || depName == "" {
			t.Skip()
		}

		// Build result
		resultsByStep := make(map[string]StepResult)
		if hasPassed {
			resultsByStep[stepName] = StepResult{
				Step: stepName,
				Passed: []source.CollectionVerificationResult{
					{
						CollectionEnvelope: source.CollectionEnvelope{
							Collection: attestation.Collection{
								Name: stepName,
							},
						},
					},
				},
			}
		} else {
			resultsByStep[stepName] = StepResult{
				Step:   stepName,
				Passed: []source.CollectionVerificationResult{},
			}
		}

		// Create step with dependency
		step := Step{
			Name:             "test",
			AttestationsFrom: []string{depName},
		}

		// checkDependencies should never panic
		err := step.checkDependencies(resultsByStep)

		// Verify behavior
		if stepName == depName && hasPassed {
			// Dependency exists and passed - should succeed
			if err != nil {
				t.Errorf("checkDependencies failed for valid dependency: %v", err)
			}
		} else {
			// Dependency missing or failed - should error
			if err == nil {
				t.Errorf("checkDependencies should fail for missing/failed dependency")
			}
		}
	})
}

// FuzzPolicyStepNames fuzzes step names to ensure they handle special characters
func FuzzPolicyStepNames(f *testing.F) {
	// Seed corpus with special characters
	f.Add("step-1", "step-2")
	f.Add("step.1", "step.2")
	f.Add("step_1", "step_2")
	f.Add("STEP", "step")
	f.Add("step/1", "step\\2")
	f.Add("step@1", "step#2")
	f.Add("step[1]", "step(2)")
	f.Add("", "step") // Empty name

	f.Fuzz(func(t *testing.T, name1, name2 string) {
		// Skip if both names are empty
		if name1 == "" && name2 == "" {
			t.Skip()
		}

		// Skip if names are identical (would create invalid policy)
		if name1 == name2 && name1 != "" {
			t.Skip()
		}

		policy := Policy{
			Steps: make(map[string]Step),
		}

		if name1 != "" {
			policy.Steps[name1] = Step{
				Name:             name1,
				AttestationsFrom: []string{},
			}
		}

		if name2 != "" {
			policy.Steps[name2] = Step{
				Name:             name2,
				AttestationsFrom: []string{name1}, // Depend on name1
			}
		}

		// Should never panic, even with unusual names
		_ = policy.Validate()
		_, _ = policy.topologicalSort()
	})
}

// FuzzMultipleDepthDependencies fuzzes deeply nested dependency chains
func FuzzMultipleDepthDependencies(f *testing.F) {
	// Seed with various depth patterns
	f.Add(3, true)  // Depth 3, valid
	f.Add(5, true)  // Depth 5, valid
	f.Add(10, true) // Depth 10, valid
	f.Add(3, false) // Depth 3, with cycle
	f.Add(1, true)  // Depth 1

	f.Fuzz(func(t *testing.T, depth int, valid bool) {
		// Limit depth to prevent resource exhaustion
		if depth < 1 || depth > 20 {
			t.Skip()
		}

		policy := Policy{
			Steps: make(map[string]Step),
		}

		// Build chain: step0 -> step1 -> step2 -> ... -> stepN
		lastStepName := string(rune('a' + depth - 1))
		for i := 0; i < depth; i++ {
			stepName := string(rune('a' + i))
			var deps []string
			if i == 0 {
				if !valid {
					// Create cycle: first step depends on last
					deps = []string{lastStepName}
				}
			} else {
				// All other steps depend on previous step
				deps = []string{string(rune('a' + i - 1))}
			}

			policy.Steps[stepName] = Step{
				Name:             stepName,
				AttestationsFrom: deps,
			}
		}

		// Validate should handle deep chains
		err := policy.Validate()

		if valid {
			if err != nil {
				t.Errorf("valid chain of depth %d should not error: %v", depth, err)
			}
		} else {
			if err == nil {
				t.Errorf("cycle in chain of depth %d should error", depth)
			}
		}
	})
}
