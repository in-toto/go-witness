// Copyright 2026 The Witness Contributors
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

package pkcs11

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/in-toto/go-witness/registry"
	"github.com/in-toto/go-witness/signer"
	"github.com/stretchr/testify/require"
)

// TestRegistryOptions sets every option the way the witness CLI does: through
// the setters of the registry entry.
func TestRegistryOptions(t *testing.T) {
	var entry *registry.Entry[signer.SignerProvider]
	for _, e := range signer.RegistryEntries() {
		if e.Name == "pkcs11" {
			entry = &e
		}
	}
	require.NotNil(t, entry, "pkcs11 signer provider is not registered")

	sp, err := signer.NewSignerProvider("pkcs11")
	require.NoError(t, err)
	names := []string{}
	for _, opt := range entry.Options {
		// The CLI creates flags only for a few option types; string is one.
		strOpt, ok := opt.(*registry.ConfigOption[signer.SignerProvider, string])
		require.True(t, ok, "option %v is not a string option", opt.Name())
		require.Empty(t, strOpt.DefaultVal())
		sp, err = strOpt.Setter()(sp, "value of "+opt.Name())
		require.NoError(t, err)
		names = append(names, opt.Name())
	}

	require.Equal(t, []string{"module-path", "token-label", "key-label", "pin-env"}, names)
	require.Equal(t, &PKCS11SignerProvider{
		modulePath: "value of module-path",
		tokenLabel: "value of token-label",
		keyLabel:   "value of key-label",
		pinEnv:     "value of pin-env",
	}, sp)
}

func TestSignerOptionErrors(t *testing.T) {
	const pinEnv = "WITNESS_TEST_PKCS11_PIN"
	missing := filepath.Join(t.TempDir(), "no-such-module.so")
	tests := []struct {
		name    string
		opts    []Option
		pin     string
		wantErr string
	}{
		{
			name:    "no module path",
			opts:    []Option{WithTokenLabel("t"), WithKeyLabel("k"), WithPINEnv(pinEnv)},
			wantErr: "module-path is a required option",
		},
		{
			name:    "no token label",
			opts:    []Option{WithModulePath(missing), WithKeyLabel("k"), WithPINEnv(pinEnv)},
			wantErr: "token-label is a required option",
		},
		{
			name:    "no key label",
			opts:    []Option{WithModulePath(missing), WithTokenLabel("t"), WithPINEnv(pinEnv)},
			wantErr: "key-label is a required option",
		},
		{
			name:    "no pin variable name",
			opts:    []Option{WithModulePath(missing), WithTokenLabel("t"), WithKeyLabel("k")},
			wantErr: "pin-env is a required option",
		},
		{
			name:    "pin variable not set",
			opts:    []Option{WithModulePath(missing), WithTokenLabel("t"), WithKeyLabel("k"), WithPINEnv(pinEnv)},
			wantErr: "the environment variable named by pin-env is empty or not set",
		},
		{
			// Either the module cannot be loaded or the platform is not supported.
			name:    "module cannot be opened",
			opts:    []Option{WithModulePath(missing), WithTokenLabel("t"), WithKeyLabel("k"), WithPINEnv(pinEnv)},
			pin:     "1234",
			wantErr: "pkcs11: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(pinEnv, tt.pin)
			s, err := New(tt.opts...).Signer(context.Background())
			require.ErrorContains(t, err, tt.wantErr)
			require.Nil(t, s)
		})
	}
}
