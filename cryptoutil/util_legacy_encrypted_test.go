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

package cryptoutil

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTryParseKeyFromReaderWithPassword_LegacyEncryptedRSA(t *testing.T) {
	// Generate RSA private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Marshal to PKCS#1 DER
	der := x509.MarshalPKCS1PrivateKey(priv)

	pass := []byte("s3cret-passphrase")

	// Encrypt PEM block using legacy PEM encryption
	encBlock, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", der, pass, x509.PEMCipherAES256) //nolint:staticcheck // legacy PEM encryption test
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(encBlock)

	// Correct passphrase parses successfully
	parsed, err := TryParseKeyFromReaderWithPassword(bytes.NewReader(pemBytes), pass)
	require.NoError(t, err)
	_, ok := parsed.(*rsa.PrivateKey)
	require.True(t, ok, "expected *rsa.PrivateKey")

	// Incorrect passphrase fails
	_, err = TryParseKeyFromReaderWithPassword(bytes.NewReader(pemBytes), []byte("wrong"))
	require.Error(t, err)
}
