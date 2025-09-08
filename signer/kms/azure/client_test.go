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

package azure

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseReference(t *testing.T) {
	tests := []struct {
		name      string
		ref       string
		wantVault string
		wantKey   string
		wantVer   string
		wantError bool
	}{
		{
			name:      "valid reference without version",
			ref:       "azurekms://test-vault.vault.azure.net/test-key",
			wantVault: "https://test-vault.vault.azure.net/",
			wantKey:   "test-key",
			wantVer:   "",
		},
		{
			name:      "valid reference with version",
			ref:       "azurekms://test-vault.vault.azure.net/test-key/1234567890abcdef",
			wantVault: "https://test-vault.vault.azure.net/",
			wantKey:   "test-key",
			wantVer:   "1234567890abcdef",
		},
		{
			name:      "invalid reference - wrong scheme",
			ref:       "awskms://test-vault.vault.azure.net/test-key",
			wantError: true,
		},
		{
			name:      "invalid reference - missing vault",
			ref:       "azurekms:///test-key",
			wantError: true,
		},
		{
			name:      "invalid reference - missing key",
			ref:       "azurekms://test-vault.vault.azure.net/",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vault, key, ver, err := ParseReference(tt.ref)
			if tt.wantError {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.wantVault, vault)
			assert.Equal(t, tt.wantKey, key)
			assert.Equal(t, tt.wantVer, ver)
		})
	}
}

func TestValidReference(t *testing.T) {
	tests := []struct {
		name      string
		ref       string
		wantError bool
	}{
		{
			name: "valid reference",
			ref:  "azurekms://test-vault.vault.azure.net/test-key",
		},
		{
			name: "valid reference with version",
			ref:  "azurekms://test-vault.vault.azure.net/test-key/version123",
		},
		{
			name:      "invalid scheme",
			ref:       "gcpkms://test-vault.vault.azure.net/test-key",
			wantError: true,
		},
		{
			name:      "missing vault name",
			ref:       "azurekms:///test-key",
			wantError: true,
		},
		{
			name:      "invalid vault format",
			ref:       "azurekms://test-vault/test-key",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidReference(tt.ref)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
