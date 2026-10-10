// Copyright 2025 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package configuration

import (
	"crypto"
	"os"
	"path/filepath"
	"testing"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/product"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestName(t *testing.T) {
	attestor := New()
	assert.Equal(t, "configuration", attestor.Name())
}

func TestType(t *testing.T) {
	attestor := New()
	assert.Equal(t, "https://witness.dev/attestations/configuration/v0.1", attestor.Type())
}

func TestRunType(t *testing.T) {
	attestor := New()
	assert.Equal(t, attestation.PreMaterialRunType, attestor.RunType())
}

func TestAttest_CommandLineRecordedVerbatim(t *testing.T) {
	args := []string{"witness", "run", "-a", "git", "-a", "slsa", "--step", "build", "--", "go", "build", "."}
	attestor := New(WithCommandLine(args))

	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor})
	require.NoError(t, err)
	require.NoError(t, attestor.Attest(ctx))

	assert.Equal(t, args, attestor.CommandLine)
}

func TestAttest_NoCommandLineByDefault(t *testing.T) {
	attestor := New()

	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor})
	require.NoError(t, err)
	require.NoError(t, attestor.Attest(ctx))

	assert.Empty(t, attestor.CommandLine)
}

func TestAttest_ResolvedConfig(t *testing.T) {
	resolved := map[string]ResolvedValue{
		"step":                 {Value: "build", Source: "commandline"},
		"attestors":            {Value: []string{"git", "slsa"}, Source: "commandline"},
		"trace":                {Value: "false", Source: "default"},
		"signer-file-key-path": {Value: "testkey.pem", Source: "config"},
	}
	attestor := New(WithResolvedConfig(resolved))

	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor})
	require.NoError(t, err)
	require.NoError(t, attestor.Attest(ctx))

	assert.Equal(t, resolved, attestor.Resolved)
}

func TestAttest_NoConfigFile(t *testing.T) {
	// ConfigPath stays empty so callers can distinguish "no config used"
	// from a loaded file. Witness no longer defaults to .witness.yaml.
	attestor := New()

	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor})
	require.NoError(t, err)
	require.NoError(t, attestor.Attest(ctx))

	assert.Empty(t, attestor.ConfigPath)
	assert.Empty(t, attestor.ConfigDigest)
	assert.Empty(t, attestor.ConfigContent)
}

func TestAttest_MissingConfigFileErrors(t *testing.T) {
	attestor := New(WithConfigFile("does-not-exist.yaml"))

	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor})
	require.NoError(t, err)
	assert.Error(t, attestor.Attest(ctx))
}

func TestAttest_ConfigFileDigestAndContent(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "witness.yaml")

	configContent := `run:
  signer-file-key-path: testkey.pem
  trace: false
verify:
  attestations:
    - "test-att.json"
  policy: policy-signed.json
  publickey: testpub.pem
`
	require.NoError(t, os.WriteFile(configPath, []byte(configContent), 0644))

	attestor := New(WithConfigFile(configPath))

	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor})
	require.NoError(t, err)
	require.NoError(t, attestor.Attest(ctx))

	assert.Equal(t, configPath, attestor.ConfigPath)
	assert.NotEmpty(t, attestor.ConfigDigest)

	digestValue, exists := attestor.ConfigDigest[cryptoutil.DigestValue{
		Hash:    crypto.SHA256,
		GitOID:  false,
		DirHash: false,
	}]
	assert.True(t, exists, "SHA256 digest should exist")
	assert.Len(t, digestValue, 64, "SHA256 should be 64 hex characters")

	runConfig, ok := attestor.ConfigContent["run"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "testkey.pem", runConfig["signer-file-key-path"])
	assert.Equal(t, false, runConfig["trace"])

	verifyConfig, ok := attestor.ConfigContent["verify"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "policy-signed.json", verifyConfig["policy"])
	assert.Equal(t, "testpub.pem", verifyConfig["publickey"])

	attestations, ok := verifyConfig["attestations"].([]any)
	require.True(t, ok)
	assert.Len(t, attestations, 1)
	assert.Equal(t, "test-att.json", attestations[0])
}

type fakeConfigurableAttestor struct {
	config map[string]any
}

func (f *fakeConfigurableAttestor) Name() string { return "fake" }
func (f *fakeConfigurableAttestor) Type() string { return "https://witness.dev/attestations/fake/v0.1" }
func (f *fakeConfigurableAttestor) RunType() attestation.RunType {
	return attestation.PostProductRunType
}
func (f *fakeConfigurableAttestor) Schema() *jsonschema.Schema { return &jsonschema.Schema{} }
func (f *fakeConfigurableAttestor) Attest(ctx *attestation.AttestationContext) error {
	return nil
}
func (f *fakeConfigurableAttestor) Configuration() map[string]any { return f.config }

func TestAttest_CollectsAttestorConfigurations(t *testing.T) {
	fake := &fakeConfigurableAttestor{config: map[string]any{"fake-option": 42}}
	prod := product.New(product.WithIncludeGlob("*.tar.gz"))
	attestor := New()

	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor, fake, prod})
	require.NoError(t, err)
	require.NoError(t, attestor.Attest(ctx))

	require.Contains(t, attestor.Attestors, "fake")
	assert.Equal(t, map[string]any{"fake-option": 42}, attestor.Attestors["fake"])

	require.Contains(t, attestor.Attestors, "product")
	assert.Equal(t, "*.tar.gz", attestor.Attestors["product"]["include-glob"])

	assert.NotContains(t, attestor.Attestors, "configuration")
}

func TestAttest_WorkingDir(t *testing.T) {
	attestor := New()

	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor}, attestation.WithWorkingDir("/some/dir"))
	require.NoError(t, err)
	require.NoError(t, attestor.Attest(ctx))

	assert.Equal(t, "/some/dir", attestor.WorkingDir)
}
