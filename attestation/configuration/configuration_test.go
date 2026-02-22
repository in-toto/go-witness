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
	"github.com/in-toto/go-witness/cryptoutil"
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

func TestAttest_BasicFlagCapture(t *testing.T) {
	attestor := New(WithCustomArgs(func() []string {
		return []string{"witness", "run", "-a", "configuration", "--step", "build", "-o", "output.json"}
	}))
	a := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{a})
	require.NoError(t, err)
	err = attestor.Attest(ctx)
	require.NoError(t, err)
	err = ctx.RunAttestors()
	require.NoError(t, err)

	assert.Equal(t, "configuration", attestor.Flags["a"])
	assert.Equal(t, "build", attestor.Flags["step"])
	assert.Equal(t, "output.json", attestor.Flags["o"])
}

func TestAttest_MixedFlagFormats(t *testing.T) {
	attestor := New(WithCustomArgs(func() []string {
		return []string{
			"witness", "run",
			"-a", "configuration",
			"--step=build",
			"--trace",
			"-o", "output.json",
		}
	}))

	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)
	err = attestor.Attest(ctx)
	require.NoError(t, err)

	assert.Equal(t, "configuration", attestor.Flags["a"])
	assert.Equal(t, "build", attestor.Flags["step"])
	assert.Equal(t, "true", attestor.Flags["trace"])
	assert.Equal(t, "output.json", attestor.Flags["o"])
}

func TestAttest_FlagsWithCommandSeparator(t *testing.T) {
	attestor := New(WithCustomArgs(func() []string {
		return []string{
			"witness", "run",
			"-a", "configuration",
			"--step", "build",
			"--",
			"go", "build", ".",
		}
	}))

	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)
	err = attestor.Attest(ctx)
	require.NoError(t, err)

	// Should only capture witness flags, not command after --
	assert.Equal(t, "configuration", attestor.Flags["a"])
	assert.Equal(t, "build", attestor.Flags["step"])
	assert.Len(t, attestor.Flags, 2)
}

func TestAttest_CustomConfigPathLongFlag(t *testing.T) {
	attestor := New(WithCustomArgs(func() []string {
		return []string{"witness", "run", "--config", "custom.yaml"}
	}))

	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)
	err = attestor.Attest(ctx)
	require.NoError(t, err)

	assert.Equal(t, "custom.yaml", attestor.ConfigPath)
}

func TestExtractWitnessArgs(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected []string
	}{
		{
			name:     "no separator",
			args:     []string{"witness", "run", "-a", "configuration"},
			expected: []string{"witness", "run", "-a", "configuration"},
		},
		{
			name:     "with separator",
			args:     []string{"witness", "run", "-a", "configuration", "--", "go", "build", "."},
			expected: []string{"witness", "run", "-a", "configuration"},
		},
		{
			name:     "separator at end",
			args:     []string{"witness", "run", "--"},
			expected: []string{"witness", "run"},
		},
		{
			name:     "empty args",
			args:     []string{},
			expected: []string{},
		},
		{
			name:     "only command after separator",
			args:     []string{"witness", "run", "--", "bash", "-c", "echo hi"},
			expected: []string{"witness", "run"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractWitnessArgs(tt.args)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseFlags(t *testing.T) {
	tests := []struct {
		name     string
		cmd      []string
		expected map[string]string
	}{
		{
			name:     "empty command",
			cmd:      []string{"witness"},
			expected: map[string]string{},
		},
		{
			name: "single long flag with space",
			cmd:  []string{"witness", "--step", "build"},
			expected: map[string]string{
				"step": "build",
			},
		},
		{
			name: "single short flag",
			cmd:  []string{"witness", "-a", "configuration"},
			expected: map[string]string{
				"a": "configuration",
			},
		},
		{
			name: "flag with equals",
			cmd:  []string{"witness", "--step=build"},
			expected: map[string]string{
				"step": "build",
			},
		},
		{
			name: "short flag with equals",
			cmd:  []string{"witness", "-o=output.json"},
			expected: map[string]string{
				"o": "output.json",
			},
		},
		{
			name: "boolean flag",
			cmd:  []string{"witness", "--trace"},
			expected: map[string]string{
				"trace": "true",
			},
		},
		{
			name: "multiple flags mixed",
			cmd:  []string{"witness", "-a", "configuration", "--step", "build", "--trace"},
			expected: map[string]string{
				"a":     "configuration",
				"step":  "build",
				"trace": "true",
			},
		},
		{
			name: "flags with special characters",
			cmd:  []string{"witness", "--rekor-server", "https://rekor.sigstore.dev"},
			expected: map[string]string{
				"rekor-server": "https://rekor.sigstore.dev",
			},
		},
		{
			name: "flags with paths",
			cmd:  []string{"witness", "--key", "/path/to/key.pem", "-o", "./output.json"},
			expected: map[string]string{
				"key": "/path/to/key.pem",
				"o":   "./output.json",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseFlags(tt.cmd)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfigDigest_ValidYAML(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, ".witness.yaml")

	configContent := `run:
  signer-file-key-path: testkey.pem
  trace: false
verify:
  attestations:
    - "test-att.json"
  policy: policy-signed.json
  publickey: testpub.pem
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	oldDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(tempDir))
	t.Cleanup(func() { _ = os.Chdir(oldDir) })

	attestor := New(WithCustomArgs(func() []string {
		return []string{"witness", "run"}
	}))

	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)
	err = attestor.Attest(ctx)
	require.NoError(t, err)

	// Verify digest is calculated
	assert.NotNil(t, attestor.ConfigDigest)
	assert.NotEmpty(t, attestor.ConfigDigest)

	// Verify SHA256 digest exists
	digestValue, exists := attestor.ConfigDigest[cryptoutil.DigestValue{
		Hash:    crypto.SHA256,
		GitOID:  false,
		DirHash: false,
	}]
	assert.True(t, exists, "SHA256 digest should exist")
	assert.NotEmpty(t, digestValue)
	assert.Len(t, digestValue, 64, "SHA256 should be 64 hex characters")

	// Verify content is parsed
	assert.NotNil(t, attestor.ConfigContent)

	// Verify run section
	runConfig, ok := attestor.ConfigContent["run"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "testkey.pem", runConfig["signer-file-key-path"])
	assert.Equal(t, false, runConfig["trace"])

	// Verify verify section
	verifyConfig, ok := attestor.ConfigContent["verify"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "policy-signed.json", verifyConfig["policy"])
	assert.Equal(t, "testpub.pem", verifyConfig["publickey"])

	attestations, ok := verifyConfig["attestations"].([]interface{})
	require.True(t, ok)
	assert.Len(t, attestations, 1)
	assert.Equal(t, "test-att.json", attestations[0])
}
