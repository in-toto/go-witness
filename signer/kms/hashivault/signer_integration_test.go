//go:build integration

// Copyright 2024 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hashivault

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"os"
	"testing"

	"github.com/in-toto/go-witness/signer/kms"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/vault"
)

const (
	testKeyName = "test-signing-key"
)

var (
	vaultContainer *vault.VaultContainer
	vaultAddr      string
	vaultToken     string
)

// TestMain manages the lifecycle of the Vault container for all tests
func TestMain(m *testing.M) {
	ctx := context.Background()

	// Start Vault container
	var err error
	vaultContainer, vaultAddr, vaultToken, err = setupVaultContainer(ctx)
	if err != nil {
		panic("failed to setup vault container: " + err.Error())
	}

	// Run tests
	code := m.Run()

	// Cleanup
	if err := vaultContainer.Terminate(ctx); err != nil {
		panic("failed to terminate vault container: " + err.Error())
	}

	os.Exit(code)
}

// setupVaultContainer initializes a Vault container with transit engine enabled
func setupVaultContainer(ctx context.Context) (*vault.VaultContainer, string, string, error) {
	const token = "test-token-12345"

	container, err := vault.Run(
		ctx,
		"hashicorp/vault:1.15",
		vault.WithToken(token),
		vault.WithInitCommand(
			"secrets enable transit",
			fmt.Sprintf("write -f transit/keys/%v type=rsa-2048", testKeyName),
		),
		testcontainers.WithEnv(map[string]string{
			"VAULT_DEV_ROOT_TOKEN_ID": token,
		}),
	)
	if err != nil {
		return nil, "", "", err
	}

	addr, err := container.HttpHostAddress(ctx)
	if err != nil {
		return nil, "", "", err
	}

	return container, addr, token, nil
}

// createTestKMSProvider creates a KMSSignerProvider for testing
func createTestKMSProvider(t *testing.T, keyName string, hashFunc crypto.Hash) *kms.KMSSignerProvider {
	t.Helper()

	clientOpts := &clientOptions{
		addr:                    vaultAddr,
		transitSecretEnginePath: "transit",
		authMethod:              "token",
		// tokenPath left empty - uses VAULT_TOKEN env var
	}

	ksp := &kms.KMSSignerProvider{
		Reference:  "hashivault://" + keyName,
		HashFunc:   hashFunc,
		KeyVersion: "0", // 0 = latest version
		Options: map[string]kms.KMSClientOptions{
			providerName: clientOpts,
		},
	}

	return ksp
}

func TestLoadSignerVerifier(t *testing.T) {
	ctx := context.Background()
	t.Setenv("VAULT_TOKEN", vaultToken)

	ksp := createTestKMSProvider(t, testKeyName, crypto.SHA256)
	sv, err := LoadSignerVerifier(ctx, ksp)
	require.NoError(t, err)
	require.NotNil(t, sv)

	keyID, err := sv.KeyID()
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("hashivault://%v", testKeyName), keyID)
}

func TestSignAndVerify(t *testing.T) {
	tests := []struct {
		name     string
		keyName  string
		hashFunc crypto.Hash
		message  string
	}{
		{
			name:     "SHA-224",
			keyName:  testKeyName,
			hashFunc: crypto.SHA224,
			message:  "test message for sha224",
		},
		{
			name:     "SHA-256",
			keyName:  testKeyName,
			hashFunc: crypto.SHA256,
			message:  "test message for sha256",
		},
		{
			name:     "SHA-384",
			keyName:  testKeyName,
			hashFunc: crypto.SHA384,
			message:  "test message for sha384",
		},
		{
			name:     "SHA-512",
			keyName:  testKeyName,
			hashFunc: crypto.SHA512,
			message:  "test message for sha512",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			t.Setenv("VAULT_TOKEN", vaultToken)

			ksp := createTestKMSProvider(t, tt.keyName, tt.hashFunc)
			sv, err := LoadSignerVerifier(ctx, ksp)
			require.NoError(t, err)

			sig, err := sv.Sign(bytes.NewReader([]byte(tt.message)))
			require.NoError(t, err)
			require.NotNil(t, sig)
			require.Greater(t, len(sig), 0)

			require.NoError(t, sv.Verify(bytes.NewReader([]byte(tt.message)), sig))
		})
	}
}

func TestVerify_InvalidSignature(t *testing.T) {
	ctx := context.Background()
	t.Setenv("VAULT_TOKEN", vaultToken)

	ksp := createTestKMSProvider(t, testKeyName, crypto.SHA256)
	sv, err := LoadSignerVerifier(ctx, ksp)
	require.NoError(t, err)

	message := "original message"
	sig, err := sv.Sign(bytes.NewReader([]byte(message)))
	require.NoError(t, err)

	// Verify with different message - should fail
	differentMessage := "different message"
	err = sv.Verify(bytes.NewReader([]byte(differentMessage)), sig)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed verification")
}

func TestGetPublicKey(t *testing.T) {
	ctx := context.Background()
	t.Setenv("VAULT_TOKEN", vaultToken)

	ksp := createTestKMSProvider(t, testKeyName, crypto.SHA256)
	sv, err := LoadSignerVerifier(ctx, ksp)
	require.NoError(t, err)

	pubKeyBytes, err := sv.Bytes()
	require.NoError(t, err)
	require.NotNil(t, pubKeyBytes)
	require.Greater(t, len(pubKeyBytes), 0)

	// Public key should be in PEM format for RSA keys
	require.Contains(t, string(pubKeyBytes), "BEGIN")
}

func TestInvalidReference(t *testing.T) {
	tests := []struct {
		name      string
		reference string
	}{
		{
			name:      "empty reference",
			reference: "",
		},
		{
			name:      "invalid scheme",
			reference: "gcpkms://test-key",
		},
		{
			name:      "missing scheme",
			reference: "test-key",
		},
		{
			name:      "invalid format with special chars",
			reference: "hashivault://test@key#name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			t.Setenv("VAULT_TOKEN", vaultToken)

			clientOpts := &clientOptions{
				addr:                    vaultAddr,
				transitSecretEnginePath: "transit",
				authMethod:              "token",
			}

			ksp := &kms.KMSSignerProvider{
				Reference:  tt.reference,
				HashFunc:   crypto.SHA256,
				KeyVersion: "0",
				Options: map[string]kms.KMSClientOptions{
					providerName: clientOpts,
				},
			}

			_, err := LoadSignerVerifier(ctx, ksp)
			require.Error(t, err)
			require.Contains(t, err.Error(), "vault ref")
		})
	}
}

func TestUnsupportedHashAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		hashFunc crypto.Hash
	}{
		{
			name:     "MD5",
			hashFunc: crypto.MD5,
		},
		{
			name:     "SHA1",
			hashFunc: crypto.SHA1,
		},
		{
			name:     "RIPEMD160",
			hashFunc: crypto.RIPEMD160,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			t.Setenv("VAULT_TOKEN", vaultToken)

			ksp := createTestKMSProvider(t, testKeyName, tt.hashFunc)
			_, err := LoadSignerVerifier(ctx, ksp)
			require.Error(t, err)
			require.Contains(t, err.Error(), "does not support provided hash function")
		})
	}
}

func TestKeyVersion(t *testing.T) {
	ctx := context.Background()
	t.Setenv("VAULT_TOKEN", vaultToken)

	tests := []struct {
		name       string
		keyVersion string
		wantErr    bool
	}{
		{
			name:       "latest version (0)",
			keyVersion: "0",
			wantErr:    false,
		},
		{
			name:       "specific version (1)",
			keyVersion: "1",
			wantErr:    false,
		},
		{
			name:       "invalid version (non-numeric)",
			keyVersion: "abc",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientOpts := &clientOptions{
				addr:                    vaultAddr,
				transitSecretEnginePath: "transit",
				authMethod:              "token",
			}

			ksp := &kms.KMSSignerProvider{
				Reference:  fmt.Sprintf("hashivault://%v", testKeyName),
				HashFunc:   crypto.SHA256,
				KeyVersion: tt.keyVersion,
				Options: map[string]kms.KMSClientOptions{
					providerName: clientOpts,
				},
			}

			sv, err := LoadSignerVerifier(ctx, ksp)
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), "invalid vault key version")
			} else {
				require.NoError(t, err)
				require.NotNil(t, sv)
			}
		})
	}
}
