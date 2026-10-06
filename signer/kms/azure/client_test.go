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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestExtractECPublicKey(t *testing.T) {
	curves := []struct {
		name      string
		curve     elliptic.Curve
		curveName azkeys.CurveName
	}{
		{
			name:      "P-256",
			curve:     elliptic.P256(),
			curveName: azkeys.CurveNameP256,
		},
		{
			name:      "P-384",
			curve:     elliptic.P384(),
			curveName: azkeys.CurveNameP384,
		},
		{
			name:      "P-521",
			curve:     elliptic.P521(),
			curveName: azkeys.CurveNameP521,
		},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			pubBytes, err := priv.PublicKey.Bytes()
			require.NoError(t, err)

			coordLen := (tc.curve.Params().BitSize + 7) / 8
			require.Equal(t, 1+2*coordLen, len(pubBytes))

			xBytes := pubBytes[1 : 1+coordLen]
			yBytes := pubBytes[1+coordLen:]

			jwk := azkeys.JSONWebKey{
				Crv: &tc.curveName,
				X:   xBytes,
				Y:   yBytes,
			}

			extracted, err := extractECPublicKey(&jwk)
			require.NoError(t, err)
			require.NotNil(t, extracted)

			extractedBytes, err := extracted.Bytes()
			require.NoError(t, err)
			assert.Equal(t, pubBytes, extractedBytes)
		})
	}

	t.Run("P-256 with left padding", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		pubBytes, err := priv.PublicKey.Bytes()
		require.NoError(t, err)

		coordLen := (elliptic.P256().Params().BitSize + 7) / 8
		xBytes := pubBytes[1 : 1+coordLen]
		yBytes := pubBytes[1+coordLen:]

		crv := azkeys.CurveNameP256
		jwk := azkeys.JSONWebKey{
			Crv: &crv,
			X:   xBytes,
			Y:   yBytes,
		}

		extracted, err := extractECPublicKey(&jwk)
		require.NoError(t, err)
		require.NotNil(t, extracted)

		extractedBytes, err := extracted.Bytes()
		require.NoError(t, err)
		assert.Equal(t, pubBytes, extractedBytes)
	})

	t.Run("missing parameters", func(t *testing.T) {
		crv := azkeys.CurveNameP256
		dummy := []byte{1, 2, 3}

		_, err := extractECPublicKey(&azkeys.JSONWebKey{Crv: &crv, X: nil, Y: dummy})
		assert.Error(t, err)

		_, err = extractECPublicKey(&azkeys.JSONWebKey{Crv: &crv, X: dummy, Y: nil})
		assert.Error(t, err)

		_, err = extractECPublicKey(&azkeys.JSONWebKey{Crv: nil, X: dummy, Y: dummy})
		assert.Error(t, err)
	})

	t.Run("unsupported curve P256K", func(t *testing.T) {
		crv := azkeys.CurveNameP256K
		dummy := make([]byte, 32)
		_, err := extractECPublicKey(&azkeys.JSONWebKey{Crv: &crv, X: dummy, Y: dummy})
		assert.ErrorContains(t, err, "not supported")
	})

	t.Run("unsupported unknown curve", func(t *testing.T) {
		crv := azkeys.CurveName("unknown")
		dummy := make([]byte, 32)
		_, err := extractECPublicKey(&azkeys.JSONWebKey{Crv: &crv, X: dummy, Y: dummy})
		assert.ErrorContains(t, err, "unsupported curve")
	})

	t.Run("invalid coordinate length", func(t *testing.T) {
		crv := azkeys.CurveNameP256
		tooLong := make([]byte, 33)
		okCoord := make([]byte, 32)
		_, err := extractECPublicKey(&azkeys.JSONWebKey{Crv: &crv, X: tooLong, Y: okCoord})
		assert.ErrorContains(t, err, "invalid EC coordinate length")

		_, err = extractECPublicKey(&azkeys.JSONWebKey{Crv: &crv, X: okCoord, Y: tooLong})
		assert.ErrorContains(t, err, "invalid EC coordinate length")
	})

	t.Run("point not on curve", func(t *testing.T) {
		crv := azkeys.CurveNameP256
		invalidX := make([]byte, 32)
		invalidY := make([]byte, 32)
		invalidX[0] = 1
		invalidY[0] = 1
		_, err := extractECPublicKey(&azkeys.JSONWebKey{Crv: &crv, X: invalidX, Y: invalidY})
		assert.Error(t, err)
	})
}

func TestExtractRSAPublicKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	nBytes := priv.N.Bytes()
	eBytes := []byte{1, 0, 1} // 65537

	jwk := azkeys.JSONWebKey{
		N: nBytes,
		E: eBytes,
	}

	extracted, err := extractRSAPublicKey(&jwk)
	require.NoError(t, err)
	require.NotNil(t, extracted)
	assert.Equal(t, priv.N, extracted.N)
	assert.Equal(t, priv.E, extracted.E)

	t.Run("missing parameters", func(t *testing.T) {
		_, err := extractRSAPublicKey(&azkeys.JSONWebKey{N: nil, E: eBytes})
		assert.Error(t, err)

		_, err = extractRSAPublicKey(&azkeys.JSONWebKey{N: nBytes, E: nil})
		assert.Error(t, err)
	})
}
