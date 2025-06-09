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

// Documentation provides structured documentation for the policy package
type Documentation struct {
	Summary     string             `json:"summary" jsonschema:"title=Summary,description=Brief description of the package"`
	Description string             `json:"description" jsonschema:"title=Description,description=Detailed description of the package functionality"`
	Usage       []string           `json:"usage" jsonschema:"title=Usage,description=Common use cases and scenarios"`
	Examples    map[string]Example `json:"examples" jsonschema:"title=Examples,description=Code examples demonstrating package usage"`
}

// Example represents a code example with explanation
type Example struct {
	Description string `json:"description" jsonschema:"title=Description,description=What this example demonstrates"`
	Code        string `json:"code" jsonschema:"title=Code,description=Example code snippet"`
}

// PackageDocumentation returns the documentation for the policy package
func PackageDocumentation() Documentation {
	return Documentation{
		Summary: "Policy definition and verification for witness attestations",
		Description: `The policy package provides the core policy engine for witness, including:
- Policy structure definition with steps, functionaries, and attestations
- Certificate constraint validation for X.509-based trust
- Rego policy evaluation for attestation content
- Policy verification against collections of attestations
- Trust root and timestamp authority management`,
		Usage: []string{
			"Define multi-step software supply chain policies",
			"Specify trusted functionaries who can perform each step",
			"Require specific attestations for each step",
			"Validate attestation content with Rego policies",
			"Establish trust roots for signature verification",
		},
		Examples: map[string]Example{
			"basic_policy": {
				Description: "Create a basic two-step policy",
				Code: `policy := Policy{
	Expires: metav1.Time{Time: time.Now().Add(365 * 24 * time.Hour)},
	Steps: map[string]Step{
		"build": {
			Name: "build",
			Functionaries: []Functionary{{
				Type:        "publickey",
				PublicKeyID: "build-key",
			}},
			Attestations: []Attestation{{
				Type: "https://witness.dev/attestations/git/v0.1",
			}},
		},
		"test": {
			Name: "test",
			ArtifactsFrom: []string{"build"},
			Functionaries: []Functionary{{
				Type:        "publickey",
				PublicKeyID: "test-key",
			}},
			Attestations: []Attestation{{
				Type: "https://witness.dev/attestations/junit/v0.1",
			}},
		},
	},
}`,
			},
			"certificate_constraint": {
				Description: "Define certificate constraints for a functionary",
				Code: `functionary := Functionary{
	Type: "root",
	CertConstraint: CertConstraint{
		CommonName:    "*.example.com",
		Organizations: []string{"Example Corp"},
		Emails:        []string{"*@example.com"},
		Roots:         []string{"example-root-ca"},
	},
}`,
			},
			"rego_policy": {
				Description: "Add a Rego policy to validate attestation content",
				Code: `attestation := Attestation{
	Type: "https://witness.dev/attestations/git/v0.1",
	RegoPolicies: []RegoPolicy{{
		Name: "clean-worktree",
		Module: []byte("package git\ndeny[msg] {\n\tinput.worktreeclean == false\n\tmsg := \"git worktree must be clean\"\n}"),
	}},
}`,
			},
		},
	}
}

// StepDocumentation provides documentation specific to policy steps
type StepDocumentation struct {
	Overview    string   `json:"overview" jsonschema:"title=Overview,description=Overview of policy steps"`
	StepTypes   []string `json:"stepTypes" jsonschema:"title=Step Types,description=Common types of steps in policies"`
	Constraints []string `json:"constraints" jsonschema:"title=Constraints,description=Types of constraints that can be applied"`
}

// GetStepDocumentation returns documentation for policy steps
func GetStepDocumentation() StepDocumentation {
	return StepDocumentation{
		Overview: "Policy steps define the required attestations and trusted functionaries for each stage of your software supply chain",
		StepTypes: []string{
			"build - Compilation and packaging steps",
			"test - Testing and validation steps",
			"scan - Security scanning steps",
			"release - Publishing and deployment steps",
		},
		Constraints: []string{
			"functionaries - Who can perform this step",
			"attestations - What evidence must be produced",
			"artifactsFrom - Dependencies on previous steps",
			"regoPolicies - Content validation rules",
		},
	}
}
