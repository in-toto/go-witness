// Copyright 2021 The Witness Contributors
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

package environment

import (
	"os"
	"testing"

	"github.com/in-toto/go-witness/attestation"
	"github.com/stretchr/testify/require"
)

// TestFilterVarsEnvironment tests if enabling filter behavior works correctly.
func TestFilterVarsEnvironment(t *testing.T) {

	attestor := New(WithFilterVarsEnabled(true))
	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor})
	require.NoError(t, err)

	t.Setenv("AWS_ACCESS_KEY_ID", "super secret")
	origVars := os.Environ()
	require.NoError(t, attestor.Attest(ctx))
	for _, env := range origVars {
		origKey, _ := splitVariable(env)
		if _, inBlockList := attestor.sensitiveVarsList[origKey]; inBlockList {
			require.NotContains(t, attestor.Variables, origKey)
		} else {
			require.Contains(t, attestor.Variables, origKey)
		}
	}
}

// TestEnvironmentObfuscate tests if obfuscate normal behavior works correctly.
func TestEnvironmentObfuscate(t *testing.T) {
	attestor := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor})
	require.NoError(t, err)

	obfuscateEnvs := map[string]struct{}{"API_TOKEN": {}, "SECRET_TEXT": {}}
	secretVarValue := "secret var"
	publicVarValue := "public var"
	for k := range obfuscateEnvs {
		t.Setenv(k, secretVarValue)
	}

	notObfuscateEnvs := map[string]struct{}{"VAR_FOO": {}, "VAR_BAR": {}}
	for k := range notObfuscateEnvs {
		t.Setenv(k, publicVarValue)
	}

	origVars := os.Environ()
	require.NoError(t, attestor.Attest(ctx))
	for _, env := range origVars {
		origKey, _ := splitVariable(env)
		if _, inObfuscateList := obfuscateEnvs[origKey]; inObfuscateList {
			require.NotEqual(t, attestor.Variables[origKey], secretVarValue)
			require.Equal(t, attestor.Variables[origKey], "******")
		}

		if _, inNotObfuscateList := notObfuscateEnvs[origKey]; inNotObfuscateList {
			require.Equal(t, attestor.Variables[origKey], publicVarValue)
		}
	}
}

// TestEnvironmentObfuscateAdditional tests if the default obfuscate with additional keys works correctly.
func TestEnvironmentObfuscateAdditional(t *testing.T) {
	attestor := New(WithAdditionalKeys([]string{"MYNAME"}))
	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor})
	require.NoError(t, err)

	obfuscateEnvs := map[string]struct{}{"API_TOKEN": {}, "MYNAME": {}}
	secretVarValue := "secret var"
	publicVarValue := "public var"
	for k := range obfuscateEnvs {
		t.Setenv(k, secretVarValue)
	}

	notObfuscateEnvs := map[string]struct{}{"VAR_FOO": {}, "VAR_BAR": {}}
	for k := range notObfuscateEnvs {
		t.Setenv(k, publicVarValue)
	}

	origVars := os.Environ()
	require.NoError(t, attestor.Attest(ctx))
	for _, env := range origVars {
		origKey, _ := splitVariable(env)
		if _, inObfuscateList := obfuscateEnvs[origKey]; inObfuscateList {
			require.NotEqual(t, attestor.Variables[origKey], secretVarValue)
			require.Equal(t, attestor.Variables[origKey], "******")
		}

		if _, inNotObfuscateList := notObfuscateEnvs[origKey]; inNotObfuscateList {
			require.Equal(t, attestor.Variables[origKey], publicVarValue)
		}
	}
}

// TestEnvironmentFilterAdditional tests if enabling filter and adding additional keys works correctly.
func TestEnvironmentFilterAdditional(t *testing.T) {
	attestor := New(WithFilterVarsEnabled(true), WithAdditionalKeys([]string{"MYNAME"}))
	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor})
	require.NoError(t, err)

	filterEnvs := map[string]struct{}{"API_TOKEN": {}, "MYNAME": {}}
	secretVarValue := "secret var"
	publicVarValue := "public var"
	for k := range filterEnvs {
		t.Setenv(k, secretVarValue)
	}

	notFilterEnvs := map[string]struct{}{"VAR_FOO": {}, "VAR_BAR": {}}
	for k := range notFilterEnvs {
		t.Setenv(k, publicVarValue)
	}

	origVars := os.Environ()
	require.NoError(t, attestor.Attest(ctx))
	for _, env := range origVars {
		origKey, _ := splitVariable(env)
		if _, inFilterList := filterEnvs[origKey]; inFilterList {
			require.NotContains(t, attestor.Variables, origKey)
		}

		if _, inNotObfuscateList := notFilterEnvs[origKey]; inNotObfuscateList {
			require.Equal(t, attestor.Variables[origKey], publicVarValue)
		}
	}
}
