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
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
)

// pkcs8EncPEM is an RSA private key encoded as PKCS#8 EncryptedPrivateKeyInfo
// with passphrase "s3cret-pass". Generated via:
//
//	openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out pk.key
//	openssl pkcs8 -in pk.key -topk8 -v2 aes-256-cbc -passout pass:s3cret-pass -out pkcs8.key
const pkcs8EncPEM = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICzzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIB/LeCo2W4L0CAggA
MB0GCWCGSAFlAwQBKgQQ5gmkVv7rv6M6WbDjERbiRgSCAoAzUkppAG2+P6BPbUUC
RW3wuxLajZnznnh0C4VrafIGr/afPssySzvtoA8K/yakfyogVdHdAt1vZ6qjGkV5
Lii6Nx8Lm22QHYMOgKeJiIb6c2XMeOtm2aDBE5BdkAFEgQvjJh4QVmlsgiblwmhZ
XnVZE9lPZhB6kIx1uMM1RfoifbqNL+FR4gq/ZIqA2fZwtB+OLaa7aY8kxF/p0yHV
tU1dwUTJf5bLilcJOCvxXffBaeltg/J42TzgQtbP9l2QHAzBSESmGjd+1RHbK5fk
pTj4ZyFNUVT94VhX3zrYuog/8B48fzf9yjQwZrWBpwxGa1ubz9jKu5usjTAMdO1s
YjPImlt1m/cIbpJHO6CZjXzZAZFa6NWY3GDN3A72zc06USAWwMjVusRgcDQ9UDZz
GYkIw9eJLAW9aiY5ICqme/FDZRxGnvTCQxwAoa4q9SoEelRzAHRgb3gh9yu7IYbo
DhjkQsxTsnBKdPqpOqE015E05woGacHrpsAeT7isj7eUAfyGZck08PTKNSK1wptT
PVBQXOTkgAW+QtkHPaOHCA2KOI0LCBp5UmF3Qd7AuSC6SzxQ8CuCImG37KNcL2DG
MCoSQThYRbpnlRSdu4SfReOXgAxn0OAdEw3ZelzfJT1beTO6ywacDyAIsNmzkOaI
ZmYAzC8VtwZPPGlSOaHRZ2oNEpB36GKiXFpcBq7KpGXP7L7XpjBJ/A81zp5RvUa4
dqDYDv5cT2im2HU6HxYCJT1nw6n7MB1p99tQIufHTYsa5HlFxTl1WZlWjkeSd1Gd
zRUMp83etY/en4xYDagth5IUz9IGNsqauXf11xcDIBy6twew6QY+oER8xKaimgQ3
zfmC
-----END ENCRYPTED PRIVATE KEY-----`

func TestTryParseKeyFromReaderWithPassword_PKCS8Encrypted_Success(t *testing.T) {
	pass := []byte("s3cret-pass")
	parsed, err := TryParseKeyFromReaderWithPassword(bytes.NewReader([]byte(pkcs8EncPEM)), pass)
	require.NoError(t, err)

	if _, ok := parsed.(*rsa.PrivateKey); !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", parsed)
	}
}

func TestTryParseKeyFromReaderWithPassword_PKCS8Encrypted_WrongPass(t *testing.T) {
	_, err := TryParseKeyFromReaderWithPassword(bytes.NewReader([]byte(pkcs8EncPEM)), []byte("wrong"))
	require.Error(t, err)
}
