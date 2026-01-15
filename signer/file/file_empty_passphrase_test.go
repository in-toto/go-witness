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

package file

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/stretchr/testify/require"
)

// generateSigstoreKeyWithEmptyPassphrase creates a sigstore-encrypted key PEM
// with an empty passphrase for testing purposes.
func generateSigstoreKeyWithEmptyPassphrase(t *testing.T) []byte {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)

	encBytes, err := encrypted.Encrypt(der, []byte(""))
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED SIGSTORE PRIVATE KEY",
		Bytes: encBytes,
	})

	return pemBytes
}

func TestFileSignerProvider_EmptyPassphrase_Explicit(t *testing.T) {
	dir := t.TempDir()
	keyPEM := generateSigstoreKeyWithEmptyPassphrase(t)
	keyPath := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0600))

	// Use explicit empty passphrase via WithKeyPassphrase("")
	fsp := New(WithKeyPath(keyPath), WithKeyPassphrase(""))
	s, err := fsp.Signer(context.Background())
	require.NoError(t, err)

	v, err := s.Verifier()
	require.NoError(t, err)

	msg := []byte("hello-empty-passphrase-explicit")
	sig, err := s.Sign(bytes.NewReader(msg))
	require.NoError(t, err)
	require.NoError(t, v.Verify(bytes.NewReader(msg), sig))
}

func TestFileSignerProvider_EmptyPassphrase_FromFile(t *testing.T) {
	dir := t.TempDir()
	keyPEM := generateSigstoreKeyWithEmptyPassphrase(t)
	keyPath := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0600))

	// Empty passphrase file (no content)
	passPath := filepath.Join(dir, "pass.txt")
	require.NoError(t, os.WriteFile(passPath, []byte(""), 0600))

	fsp := New(WithKeyPath(keyPath), WithKeyPassphrasePath(passPath))
	s, err := fsp.Signer(context.Background())
	require.NoError(t, err)

	v, err := s.Verifier()
	require.NoError(t, err)

	msg := []byte("hello-empty-passphrase-file")
	sig, err := s.Sign(bytes.NewReader(msg))
	require.NoError(t, err)
	require.NoError(t, v.Verify(bytes.NewReader(msg), sig))
}

func TestFileSignerProvider_EmptyPassphrase_FromFileWithNewline(t *testing.T) {
	dir := t.TempDir()
	keyPEM := generateSigstoreKeyWithEmptyPassphrase(t)
	keyPath := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0600))

	// Empty passphrase file with trailing newline (common in editors)
	passPath := filepath.Join(dir, "pass.txt")
	require.NoError(t, os.WriteFile(passPath, []byte("\n"), 0600))

	fsp := New(WithKeyPath(keyPath), WithKeyPassphrasePath(passPath))
	s, err := fsp.Signer(context.Background())
	require.NoError(t, err)

	v, err := s.Verifier()
	require.NoError(t, err)

	msg := []byte("hello-empty-passphrase-file-newline")
	sig, err := s.Sign(bytes.NewReader(msg))
	require.NoError(t, err)
	require.NoError(t, v.Verify(bytes.NewReader(msg), sig))
}

func TestFileSignerProvider_EmptyPassphrase_FromEnv(t *testing.T) {
	dir := t.TempDir()
	keyPEM := generateSigstoreKeyWithEmptyPassphrase(t)
	keyPath := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0600))

	// Set environment variable to empty string
	t.Setenv("WITNESS_KEY_PASSPHRASE", "")

	fsp := New(WithKeyPath(keyPath))
	s, err := fsp.Signer(context.Background())
	require.NoError(t, err)

	v, err := s.Verifier()
	require.NoError(t, err)

	msg := []byte("hello-empty-passphrase-env")
	sig, err := s.Sign(bytes.NewReader(msg))
	require.NoError(t, err)
	require.NoError(t, v.Verify(bytes.NewReader(msg), sig))
}

func TestFileSignerProvider_EmptyPassphrase_ExplicitPrecedence(t *testing.T) {
	dir := t.TempDir()
	keyPEM := generateSigstoreKeyWithEmptyPassphrase(t)
	keyPath := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0600))

	// Set env to wrong passphrase - explicit empty should take precedence
	t.Setenv("WITNESS_KEY_PASSPHRASE", "wrong-password")

	// Explicit empty passphrase should override the env var
	fsp := New(WithKeyPath(keyPath), WithKeyPassphrase(""))
	s, err := fsp.Signer(context.Background())
	require.NoError(t, err)

	v, err := s.Verifier()
	require.NoError(t, err)

	msg := []byte("hello-empty-passphrase-precedence")
	sig, err := s.Sign(bytes.NewReader(msg))
	require.NoError(t, err)
	require.NoError(t, v.Verify(bytes.NewReader(msg), sig))
}

func TestFileSignerProvider_SigstoreKey_NoPassphrase_Error(t *testing.T) {
	dir := t.TempDir()
	keyPEM := generateSigstoreKeyWithEmptyPassphrase(t)
	keyPath := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0600))

	// No passphrase provided at all - should fail for encrypted sigstore key
	fsp := New(WithKeyPath(keyPath))
	_, err := fsp.Signer(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "requires a passphrase")
}
