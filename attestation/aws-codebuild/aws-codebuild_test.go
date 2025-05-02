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

package aws_codebuild

import (
	"os"
	"testing"

	"github.com/in-toto/go-witness/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	attestor := New()
	assert.NotNil(t, attestor)
}

func TestAttestorName(t *testing.T) {
	attestor := New()
	assert.Equal(t, Name, attestor.Name())
}

func TestAttestorType(t *testing.T) {
	attestor := New()
	assert.Equal(t, Type, attestor.Type())
}

func TestAttestorRunType(t *testing.T) {
	attestor := New()
	assert.Equal(t, RunType, attestor.RunType())
}

func TestAttestorSchema(t *testing.T) {
	attestor := New()
	schema := attestor.Schema()
	assert.NotNil(t, schema)
}

func TestAttest(t *testing.T) {
	// Save original env vars
	origBuildID := os.Getenv(envCodeBuildBuildID)
	origBuildARN := os.Getenv(envCodeBuildBuildARN)
	origBuildNumber := os.Getenv(envCodeBuildBuildNumber)
	origProjectName := os.Getenv(envCodeBuildProjectName)
	origInitiator := os.Getenv(envCodeBuildInitiator)
	origSourceVersion := os.Getenv(envCodeBuildResolvedSrcVer)
	origSourceRepo := os.Getenv(envCodeBuildSourceRepo)

	// Cleanup env vars after test
	defer func() {
		os.Setenv(envCodeBuildBuildID, origBuildID)
		os.Setenv(envCodeBuildBuildARN, origBuildARN)
		os.Setenv(envCodeBuildBuildNumber, origBuildNumber)
		os.Setenv(envCodeBuildProjectName, origProjectName)
		os.Setenv(envCodeBuildInitiator, origInitiator)
		os.Setenv(envCodeBuildResolvedSrcVer, origSourceVersion)
		os.Setenv(envCodeBuildSourceRepo, origSourceRepo)
	}()

	t.Run("not in CodeBuild environment", func(t *testing.T) {
		os.Unsetenv(envCodeBuildBuildID)

		attestor := New()
		ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor})
		require.NoError(t, err)

		err = attestor.Attest(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not running in AWS CodeBuild environment")
	})

	t.Run("in CodeBuild environment", func(t *testing.T) {
		// Set mock env vars
		os.Setenv(envCodeBuildBuildID, "project:build-id-123")
		os.Setenv(envCodeBuildBuildARN, "arn:aws:codebuild:us-west-2:123456789012:build/project:build-id-123")
		os.Setenv(envCodeBuildBuildNumber, "1")
		os.Setenv(envCodeBuildProjectName, "my-project")
		os.Setenv(envCodeBuildInitiator, "user")
		os.Setenv(envCodeBuildResolvedSrcVer, "0123456789abcdef0123456789abcdef01234567")
		os.Setenv(envCodeBuildSourceRepo, "https://github.com/example/repo.git")

		attestor := New()
		// The new attestor will handle missing AWS config gracefully

		ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor})
		require.NoError(t, err)

		err = attestor.Attest(ctx)
		require.NoError(t, err)

		assert.Equal(t, "project:build-id-123", attestor.BuildInfo.BuildID)
		assert.Equal(t, "arn:aws:codebuild:us-west-2:123456789012:build/project:build-id-123", attestor.BuildInfo.BuildARN)
		assert.Equal(t, "1", attestor.BuildInfo.BuildNumber)
		assert.Equal(t, "my-project", attestor.BuildInfo.ProjectName)
		assert.Equal(t, "user", attestor.BuildInfo.Initiator)
		assert.Equal(t, "0123456789abcdef0123456789abcdef01234567", attestor.BuildInfo.SourceVersion)
		assert.Equal(t, "https://github.com/example/repo.git", attestor.BuildInfo.SourceRepo)
	})
}

func TestSubjects(t *testing.T) {
	// Set mock data
	attestor := New()
	attestor.BuildInfo.BuildID = "project:build-id-123"
	attestor.BuildInfo.ProjectName = "my-project"
	attestor.BuildInfo.SourceVersion = "0123456789abcdef0123456789abcdef01234567"

	subjects := attestor.Subjects()

	assert.Contains(t, subjects, "codebuild-build-id:project:build-id-123")
	assert.Contains(t, subjects, "codebuild-project:my-project")
	assert.Contains(t, subjects, "codebuild-source-version:0123456789abcdef0123456789abcdef01234567")
}

func TestBackRefs(t *testing.T) {
	// Set mock data
	attestor := New()
	attestor.BuildInfo.BuildID = "project:build-id-123"
	attestor.BuildInfo.ProjectName = "my-project"
	attestor.BuildInfo.SourceVersion = "0123456789abcdef0123456789abcdef01234567"

	backrefs := attestor.BackRefs()

	assert.Contains(t, backrefs, "codebuild-build-id:project:build-id-123")
	assert.Contains(t, backrefs, "codebuild-project:my-project")
	assert.Contains(t, backrefs, "codebuild-source-version:0123456789abcdef0123456789abcdef01234567")
}
