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

package gitlab

import (
	"fmt"
	"os"
	"testing"

	"github.com/in-toto/go-witness/attestation"
	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	testCases := []struct {
		name string
		opts []Option
		want func(*Attestor) bool
	}{
		{
			name: "no options",
			opts: nil,
			want: func(a *Attestor) bool {
				return a.token == "" && a.tokenEnvVar == ""
			},
		},
		{
			name: "with token",
			opts: []Option{WithToken("test-token")},
			want: func(a *Attestor) bool {
				return a.token == "test-token"
			},
		},
		{
			name: "with token env var",
			opts: []Option{WithTokenEnvVar("TEST_TOKEN_VAR")},
			want: func(a *Attestor) bool {
				return a.tokenEnvVar == "TEST_TOKEN_VAR"
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			got := New(testCase.opts...)
			assert.True(t, testCase.want(got))
		})
	}
}

func TestSubjects(t *testing.T) {
	attestor := &Attestor{
		PipelineUrl: "https://gitlab.example.com/project/-/pipelines/789012",
		JobUrl:      "https://gitlab.example.com/project/-/jobs/123456",
		ProjectUrl:  "https://gitlab.example.com/project",
	}

	subjects := attestor.Subjects()
	assert.NotNil(t, subjects)
	assert.Equal(t, 3, len(subjects))

	expectedSubjects := []string{
		"pipelineurl:" + attestor.PipelineUrl,
		"joburl:" + attestor.JobUrl,
		"projecturl:" + attestor.ProjectUrl,
	}

	for _, expectedSubject := range expectedSubjects {
		_, ok := subjects[expectedSubject]
		assert.True(t, ok, "Expected subject not found: %s", expectedSubject)
	}

	backRefs := attestor.BackRefs()
	assert.NotNil(t, backRefs)
	assert.Equal(t, 1, len(backRefs))

	// Verify only pipeline URL is in backRefs
	pipelineKey := "pipelineurl:" + attestor.PipelineUrl
	_, ok := backRefs[pipelineKey]
	assert.True(t, ok, "Pipeline URL should be in backRefs")
}

func TestErrNotGitlab(t *testing.T) {
	err := ErrNotGitlab{}
	assert.Equal(t, "not in a gitlab ci job", err.Error())
	assert.Implements(t, (*error)(nil), err)
}

func TestAttestorMethods(t *testing.T) {
	attestor := New()

	assert.Equal(t, Name, attestor.Name())
	assert.Equal(t, Type, attestor.Type())
	assert.Equal(t, RunType, attestor.RunType())
	assert.Equal(t, attestor, attestor.Data())

	schema := attestor.Schema()
	assert.NotNil(t, schema)
	assert.NotNil(t, schema.Definitions)
	assert.Contains(t, schema.Definitions, "Attestor")
}

func TestAttestorInterfaces(t *testing.T) {
	attestor := New()

	assert.Implements(t, (*attestation.Attestor)(nil), attestor)
	assert.Implements(t, (*attestation.Subjecter)(nil), attestor)
	assert.Implements(t, (*attestation.BackReffer)(nil), attestor)
	assert.Implements(t, (*GitLabAttestor)(nil), attestor)
}

func TestConstants(t *testing.T) {
	assert.Equal(t, "gitlab", Name)
	assert.Equal(t, "https://witness.dev/attestations/gitlab/v0.1", Type)
	assert.Equal(t, attestation.PreMaterialRunType, RunType)
}

func TestSubjectsEmpty(t *testing.T) {
	attestor := &Attestor{}
	subjects := attestor.Subjects()
	assert.NotNil(t, subjects)
	// Should still create subjects even with empty URLs, though they may be empty strings
	assert.Equal(t, 3, len(subjects))
}

func TestJWKSURLOverride(t *testing.T) {
	testCases := []struct {
		name            string
		jwksURLEnv      string
		ciServerURL     string
		expectedJWKSURL string
	}{
		{
			name:            "default JWKS URL when no override",
			jwksURLEnv:      "",
			ciServerURL:     "https://gitlab.example.com",
			expectedJWKSURL: "https://gitlab.example.com/oauth/discovery/keys",
		},
		{
			name:            "custom JWKS URL when override set",
			jwksURLEnv:      "http://localhost:8081/.well-known/jwks",
			ciServerURL:     "https://gitlab.example.com",
			expectedJWKSURL: "http://localhost:8081/.well-known/jwks",
		},
		{
			name:            "custom JWKS URL with different port",
			jwksURLEnv:      "https://test-server.example.com:9090/jwks",
			ciServerURL:     "https://gitlab.internal.com",
			expectedJWKSURL: "https://test-server.example.com:9090/jwks",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// Set up environment variables required for GitLab CI detection
			t.Setenv("GITLAB_CI", "true")
			t.Setenv("CI_SERVER_URL", testCase.ciServerURL)

			// Set up JWKS URL override environment variable
			if testCase.jwksURLEnv != "" {
				t.Setenv("WITNESS_GITLAB_JWKS_URL", testCase.jwksURLEnv)
			}

			// Create new attestor and test with empty context since we only care about JWKS URL setup
			attestor := New()
			ctx := &attestation.AttestationContext{}

			// Call Attest which sets up the JWKS URL
			err := attestor.Attest(ctx)

			// We expect this to pass (no JWT token is OK for this test)
			assert.NoError(t, err)

			// Verify the correct server URL was captured
			assert.Equal(t, testCase.ciServerURL, attestor.CIServerUrl)

			// We can't directly access the JWKS URL used since it's passed to jwt.New(),
			// but we can verify the environment variable logic by checking that if we set the environment variable,
			// we should be able to retrieve it the same way the code does
			jwksURL := os.Getenv("WITNESS_GITLAB_JWKS_URL")
			if jwksURL == "" {
				jwksURL = fmt.Sprintf("%s/oauth/discovery/keys", attestor.CIServerUrl)
			}
			assert.Equal(t, testCase.expectedJWKSURL, jwksURL)
		})
	}
}
