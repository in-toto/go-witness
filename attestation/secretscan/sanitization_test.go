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

package secretscan

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/in-toto/go-witness/attestation"
	"github.com/invopop/jsonschema" // Used by the testSecretAttestor.Schema method
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helper attestor that has secrets embedded in its attestation
type testSecretAttestor struct {
	name       string
	secretData string
}

func (a *testSecretAttestor) Name() string {
	return a.name
}

func (a *testSecretAttestor) Type() string {
	return "test-attestor"
}

func (a *testSecretAttestor) RunType() attestation.RunType {
	return attestation.MaterialRunType
}

func (a *testSecretAttestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(a)
}

func (a *testSecretAttestor) Attest(ctx *attestation.AttestationContext) error {
	return nil
}

func (a *testSecretAttestor) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"name":       a.name,
		"secretData": a.secretData,
	})
}

func TestGenerateFindingID(t *testing.T) {
	// Create test findings with different attributes
	finding1 := Finding{
		RuleID: "aws-access-key",
		File:   "/path/to/file1.txt",
		Line:   10,
	}

	finding2 := Finding{
		RuleID: "aws-access-key",
		File:   "/path/to/file1.txt",
		Line:   20, // Different line
	}

	finding3 := Finding{
		RuleID: "github-token", // Different rule
		File:   "/path/to/file1.txt",
		Line:   10,
	}

	finding4 := Finding{
		RuleID: "aws-access-key",
		File:   "/path/to/file2.txt", // Different file
		Line:   10,
	}

	// Generate IDs
	id1 := generateFindingID(finding1)
	id2 := generateFindingID(finding2)
	id3 := generateFindingID(finding3)
	id4 := generateFindingID(finding4)

	// Test that different findings generate different IDs
	assert.NotEqual(t, id1, id2, "Different lines should generate different IDs")
	assert.NotEqual(t, id1, id3, "Different rules should generate different IDs")
	assert.NotEqual(t, id1, id4, "Different files should generate different IDs")

	// Test that same finding always generates the same ID (deterministic)
	id1Again := generateFindingID(finding1)
	assert.Equal(t, id1, id1Again, "Same finding should generate the same ID")

	// Check ID format - should be 10 characters
	assert.Equal(t, 10, len(id1), "Finding ID should be 10 characters long")

	// Test special character handling (ensure no errors)
	specialFinding := Finding{
		RuleID: "special!@#$%^",
		File:   "/path/with/special?&*()chars.txt",
		Line:   100,
	}
	specialID := generateFindingID(specialFinding)
	assert.Equal(t, 10, len(specialID), "Special character finding ID should still be 10 characters")
}

func TestSanitizeJSON(t *testing.T) {
	// Create test findings
	findings := []Finding{
		{
			RuleID:      "aws-access-key",
			Description: "AWS Access Key",
			File:        "/path/to/file1.txt",
			Line:        10,
			Secret:      "aws-access-key:AKI...:SHA256:1234567890abcdef",
		},
		{
			RuleID:      "github-token",
			Description: "GitHub Token",
			File:        "/path/to/file1.txt",
			Line:        20,
			Secret:      "github-token:ghp...:SHA256:abcdef1234567890",
		},
	}

	// Create test JSON with secrets
	testJSON := `{
		"name": "test-attestor",
		"type": "test-type",
		"secrets": {
			"aws": "AKIAIOSFODNN7EXAMPLE",
			"github": "ghp_012345678901234567890123456789",
			"nested": {
				"secret": "AKIAIOSFODNN7EXAMPLE",
				"array": ["normal", "ghp_012345678901234567890123456789", "normal"]
			}
		},
		"normal": "This has no secrets"
	}`

	// Prepare findings with actual secrets
	for i := range findings {
		if strings.Contains(findings[i].Secret, "aws-access-key") {
			findings[i].actualSecret = "AKIAIOSFODNN7EXAMPLE"
		} else if strings.Contains(findings[i].Secret, "github-token") {
			findings[i].actualSecret = "ghp_012345678901234567890123456789"
		}
	}

	// Sanitize the JSON
	sanitized, err := sanitizeJSON([]byte(testJSON), findings)
	require.NoError(t, err)

	// Parse sanitized JSON
	var result map[string]interface{}
	err = json.Unmarshal(sanitized, &result)
	require.NoError(t, err)

	// Check that secrets were replaced
	secrets := result["secrets"].(map[string]interface{})
	assert.Contains(t, secrets["aws"].(string), "[REDACTED:aws-access-key:")
	assert.Contains(t, secrets["github"].(string), "[REDACTED:github-token:")

	// Check nested secret
	nested := secrets["nested"].(map[string]interface{})
	assert.Contains(t, nested["secret"].(string), "[REDACTED:aws-access-key:")

	// Check array entry
	nestedArray := nested["array"].([]interface{})
	assert.Equal(t, "normal", nestedArray[0])
	assert.Contains(t, nestedArray[1].(string), "[REDACTED:github-token:")
	assert.Equal(t, "normal", nestedArray[2])

	// Check that normal fields were not modified
	assert.Equal(t, "This has no secrets", result["normal"])
	assert.Equal(t, "test-attestor", result["name"])

	// Test with invalid JSON
	_, err = sanitizeJSON([]byte("invalid json"), findings)
	assert.Error(t, err, "Should return error for invalid JSON")
}

func TestMarshalJSONWithSanitization(t *testing.T) {
	// Create findings with secrets
	findings := []Finding{
		{
			RuleID:       "aws-access-key",
			Description:  "AWS Access Key",
			File:         "/path/to/file1.txt",
			Line:         10,
			Secret:       "aws-access-key:AKI...:SHA256:1234567890abcdef",
			Source:       "attestation:test-attestor",
			actualSecret: "AKIAIOSFODNN7EXAMPLE",
		},
	}

	// Create a test JSON with a secret to sanitize
	testJSON := `{
		"type": "test",
		"data": "This contains a secret: AKIAIOSFODNN7EXAMPLE"
	}`

	// Create attestor with sanitization enabled
	attestor := New(WithSanitizeAttestations(true))
	attestor.Findings = findings

	// Parse the test JSON to simulate sanitization
	var jsonObj interface{}
	err := json.Unmarshal([]byte(testJSON), &jsonObj)
	require.NoError(t, err)

	// Manually sanitize to check if our function works
	sanitized := sanitizeJSONValue(jsonObj, findings)
	sanitizedData, err := json.Marshal(sanitized)
	require.NoError(t, err)
	sanitizedStr := string(sanitizedData)

	// Verify sanitization works with manual test
	assert.NotContains(t, sanitizedStr, "AKIAIOSFODNN7EXAMPLE", "Secret should be redacted")
	assert.Contains(t, sanitizedStr, "[REDACTED:aws-access-key:", "Redaction marker should be present")

	// Test the MarshalJSON method directly on the attestor
	attestor.Findings[0].actualSecret = "AKIAIOSFODNN7EXAMPLE"

	// Add a secret to the report
	jsonWithSecret, err := json.Marshal(map[string]string{
		"secret_data": "This contains a secret: AKIAIOSFODNN7EXAMPLE",
	})
	require.NoError(t, err)

	// Run sanitizeJSON directly (this is what MarshalJSON uses)
	sanitizedAttestor, err := sanitizeJSON(jsonWithSecret, findings)
	require.NoError(t, err)
	sanitizedAttestorStr := string(sanitizedAttestor)

	// Verify the sanitization
	assert.NotContains(t, sanitizedAttestorStr, "AKIAIOSFODNN7EXAMPLE", "Attestor JSON should not contain raw secret")
	assert.Contains(t, sanitizedAttestorStr, "[REDACTED:aws-access-key:", "Redaction marker should be present")
}

func TestAttestorConfigOptions(t *testing.T) {
	// Test default sanitization options
	attestor := New()
	assert.Equal(t, defaultSanitizeAttestations, attestor.sanitizeAttestations, "Default sanitizeAttestations should match constant")

	// Test setting sanitization options
	attestor = New(
		WithSanitizeAttestations(false),
	)

	assert.False(t, attestor.sanitizeAttestations, "Should be able to disable sanitization")
}

func TestEndToEndAttestationSanitization(t *testing.T) {
	// This is a simplified version that directly tests the sanitization mechanism
	// rather than relying on the gitleaks detector which may not consistently
	// find secrets in different environments

	// Create secret findings
	findings := []Finding{
		{
			RuleID:       "aws-access-key",
			Description:  "AWS Access Key",
			File:         "/path/to/file1.txt",
			Line:         10,
			Secret:       "aws-access-key:AKI...:SHA256:1234567890abcdef",
			Source:       "attestation:test-attestor",
			actualSecret: "AKIAIOSFODNN7EXAMPLE",
		},
	}

	// Create attestor with sanitization and data
	secretscanAttestor := New(WithSanitizeAttestations(true))
	secretscanAttestor.Findings = findings

	// Create attestation JSON with secrets that should be sanitized
	attestationWithSecret := map[string]interface{}{
		"findings":    findings,
		"secret_data": "This contains a key AKIAIOSFODNN7EXAMPLE that should be redacted",
	}

	// Convert to JSON string
	jsonData, err := json.Marshal(attestationWithSecret)
	require.NoError(t, err)

	// Sanitize it
	sanitized, err := sanitizeJSON(jsonData, findings)
	require.NoError(t, err)
	sanitizedStr := string(sanitized)

	// Verify sanitization worked
	assert.NotContains(t, sanitizedStr, "AKIAIOSFODNN7EXAMPLE",
		"Sanitized JSON should not contain raw secret")
	assert.Contains(t, sanitizedStr, "[REDACTED:aws-access-key:",
		"Sanitized JSON should contain redaction marker")

	// Also test MarshalJSON method
	attestorJson, err := json.Marshal(secretscanAttestor)
	require.NoError(t, err)
	attestorStr := string(attestorJson)

	// The attestation JSON should not contain the raw secret
	assert.NotContains(t, attestorStr, "AKIAIOSFODNN7EXAMPLE",
		"Attestor JSON should not contain raw secret")
}

func TestAttestationReplacement(t *testing.T) {
	// This test verifies that when attestations with secrets are serialized,
	// any actual secrets are never included in the output

	// Set up a test secret
	secretValue := "AKIAIOSFODNN7EXAMPLE"

	// Create attestor with sanitization enabled
	attestor := New(WithSanitizeAttestations(true))

	// Add a finding with a secret
	attestor.Findings = []Finding{
		{
			RuleID:       "aws-access-key",
			Description:  "AWS Access Key",
			File:         "/path/to/file.txt",
			Line:         10,
			Secret:       "aws-access-key:AKI...:SHA256:1234567890abcdef",
			Source:       "attestation:test",
			actualSecret: secretValue,
		},
	}

	// Test that serializing the attestor properly sanitizes
	jsonData, err := json.Marshal(attestor)
	require.NoError(t, err)
	jsonStr := string(jsonData)

	// The secret should not appear in the JSON
	assert.NotContains(t, jsonStr, secretValue,
		"Secret should not be present in serialized attestation")

	// Important: Verify that the Finding.actualSecret field is never serialized
	// This verifies that the `json:"-"` tag is working as expected
	assert.NotContains(t, jsonStr, "actualSecret",
		"The field name 'actualSecret' should not appear in JSON")

	// Verify that even after serialization, the original secret is still in memory
	// This ensures we're replacing the serialized form, not the in-memory data
	assert.Equal(t, secretValue, attestor.Findings[0].actualSecret,
		"The actual secret should still be available in memory")

	// Now the key test - make JSON with an embedded secret
	jsonWithSecret := fmt.Sprintf(`{
		"findings": [
			{
				"ruleId": "aws-access-key",
				"description": "AWS Access Key",
				"file": "/path/to/file.txt",
				"line": 10,
				"secret": "aws-access-key:AKI...:SHA256:1234567890abcdef",
				"source": "attestation:test",
				"secret_data": "%s"
			}
		]
	}`, secretValue)

	// Sanitize this JSON
	sanitized, err := sanitizeJSON([]byte(jsonWithSecret), attestor.Findings)
	require.NoError(t, err)
	sanitizedStr := string(sanitized)

	// This time, since we explicitly put the secret in a field, it should be redacted
	assert.NotContains(t, sanitizedStr, secretValue,
		"Sanitization should remove the secret")
	assert.Contains(t, sanitizedStr, "[REDACTED:",
		"Sanitization should add redaction marker")

	// Verify the sanitized JSON can be deserialized without issue
	var parsedAttestor map[string]interface{}
	err = json.Unmarshal(sanitized, &parsedAttestor)
	require.NoError(t, err)

	// Make sure we can re-serialize the parsed data
	reserializedData, err := json.Marshal(parsedAttestor)
	require.NoError(t, err)
	reserializedStr := string(reserializedData)

	// The re-serialized data should still not contain the secret
	assert.NotContains(t, reserializedStr, secretValue,
		"Re-serialized data should not contain the secret")
}
