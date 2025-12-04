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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
)

// pemsigstorekey copied from sigstore/cosign tests; passphrase is "hello".
const pemsigstorekey = `-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----
eyJrZGYiOnsibmFtZSI6InNjcnlwdCIsInBhcmFtcyI6eyJOIjozMjc2OCwiciI6
OCwicCI6MX0sInNhbHQiOiI3T3VGd2VsbWZZNXVId2NoaURSc210anNwZ2ZlZjFG
Mk5lOGFDTjVLYVpZPSJ9LCJjaXBoZXIiOnsibmFtZSI6Im5hY2wvc2VjcmV0Ym94
Iiwibm9uY2UiOiJQNHk4OGhCb3ZTa09MbXN0bFVBaGJwdDJ0K2xTNUxQSCJ9LCJj
aXBoZXJ0ZXh0IjoiMnB1QzdyZldJOWh3bnJlQ2s4aUZDRlVwQlRrSzRJNlIvbFBF
cnBDekpXUGpJWXl4eGVIL1A2VW52cFJHdVhla1NNb3JMdGhLamdoQ1JlNy82NDVH
QWtoVm1LRC92eEF0S2EvbE1abENSQ3FlekJGUFd1dzNpeFRtZ2xhb2J1ZFVSbUVs
bmNGOGlZbzBTMVl6Y1ZOMVFwY2J2c0dNcUlYRzVlbmdteGp5dCtBcXlyZTF0Q0Y0
V01tU1BlaEljNlBqd2h1Q2xHaVpJUWRvTGc9PSJ9
-----END ENCRYPTED SIGSTORE PRIVATE KEY-----`

func TestTryParseKeyFromReaderWithPassword_SigstoreEncrypted_Success(t *testing.T) {
	parsed, err := TryParseKeyFromReaderWithPassword(bytes.NewReader([]byte(pemsigstorekey)), []byte("hello"))
	require.NoError(t, err)

	switch parsed.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
		// ok
	default:
		t.Fatalf("unexpected key type %T", parsed)
	}
}

func TestTryParseKeyFromReaderWithPassword_SigstoreEncrypted_WrongPass(t *testing.T) {
	_, err := TryParseKeyFromReaderWithPassword(bytes.NewReader([]byte(pemsigstorekey)), []byte("wrong"))
	require.Error(t, err)
}

func TestTryParseKeyFromReaderWithPassword_SigstoreEncrypted_NoPass(t *testing.T) {
	_, err := TryParseKeyFromReaderWithPassword(bytes.NewReader([]byte(pemsigstorekey)), nil)
	require.Error(t, err)
}
