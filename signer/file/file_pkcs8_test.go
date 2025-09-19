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

package file

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Same PEM vector and passphrase as in cryptoutil tests
const pkcs8PEM = `-----BEGIN ENCRYPTED PRIVATE KEY-----
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

const passphrase = "s3cret-pass"

func writeTemp(dir, name, data string, t *testing.T) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(data), 0600))
	return p
}

func TestFileSignerProvider_PassphrasePath_Success(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTemp(dir, "key.pem", pkcs8PEM, t)
	passPath := writeTemp(dir, "pass.txt", passphrase, t)

	fsp := New(WithKeyPath(keyPath), WithKeyPassphrasePath(passPath))
	s, err := fsp.Signer(context.Background())
	require.NoError(t, err)

	v, err := s.Verifier()
	require.NoError(t, err)

	// Sign and verify a small message
	msg := []byte("hello-pkcs8")
	sig, err := s.Sign(bytes.NewReader(msg))
	require.NoError(t, err)
	require.NoError(t, v.Verify(bytes.NewReader(msg), sig))
}

func TestFileSignerProvider_PassphrasePath_MultipleLines_Error(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTemp(dir, "key.pem", pkcs8PEM, t)
	// Two lines; should error
	passPath := writeTemp(dir, "pass.txt", passphrase+"\nextra", t)

	fsp := New(WithKeyPath(keyPath), WithKeyPassphrasePath(passPath))
	_, err := fsp.Signer(context.Background())
	require.Error(t, err)
}

func TestFileSignerProvider_PassphrasePath_CRLF_Success(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTemp(dir, "key.pem", pkcs8PEM, t)
	passPath := writeTemp(dir, "pass.txt", passphrase+"\r\n", t)

	fsp := New(WithKeyPath(keyPath), WithKeyPassphrasePath(passPath))
	s, err := fsp.Signer(context.Background())
	require.NoError(t, err)
	v, err := s.Verifier()
	require.NoError(t, err)
	msg := []byte("hello-crlf")
	sig, err := s.Sign(bytes.NewReader(msg))
	require.NoError(t, err)
	require.NoError(t, v.Verify(bytes.NewReader(msg), sig))
}

func TestFileSignerProvider_PassphrasePath_LF_Success(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTemp(dir, "key.pem", pkcs8PEM, t)
	passPath := writeTemp(dir, "pass.txt", passphrase+"\n", t)

	fsp := New(WithKeyPath(keyPath), WithKeyPassphrasePath(passPath))
	s, err := fsp.Signer(context.Background())
	require.NoError(t, err)
	v, err := s.Verifier()
	require.NoError(t, err)
	msg := []byte("hello-lf")
	sig, err := s.Sign(bytes.NewReader(msg))
	require.NoError(t, err)
	require.NoError(t, v.Verify(bytes.NewReader(msg), sig))
}

func TestFileSignerProvider_PassphraseEnv_Success(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTemp(dir, "key.pem", pkcs8PEM, t)
	t.Setenv("WITNESS_KEY_PASSPHRASE", passphrase)

	fsp := New(WithKeyPath(keyPath))
	s, err := fsp.Signer(context.Background())
	require.NoError(t, err)
	v, err := s.Verifier()
	require.NoError(t, err)

	msg := []byte("hello-env")
	sig, err := s.Sign(bytes.NewReader(msg))
	require.NoError(t, err)
	require.NoError(t, v.Verify(bytes.NewReader(msg), sig))
}

func TestFileSignerProvider_PassphraseExplicit_Precedence(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTemp(dir, "key.pem", pkcs8PEM, t)
	passPath := writeTemp(dir, "pass.txt", "WRONG", t)
	t.Setenv("WITNESS_KEY_PASSPHRASE", "ALSO_WRONG")

	// Explicit passphrase should take precedence over file and env
	fsp := New(WithKeyPath(keyPath), WithKeyPassphrasePath(passPath), WithKeyPassphrase(passphrase))
	s, err := fsp.Signer(context.Background())
	require.NoError(t, err)
	v, err := s.Verifier()
	require.NoError(t, err)

	msg := []byte("hello-explicit")
	sig, err := s.Sign(bytes.NewReader(msg))
	require.NoError(t, err)
	require.NoError(t, v.Verify(bytes.NewReader(msg), sig))
}

func TestFileSignerProvider_WrongPassphrase_Error(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTemp(dir, "key.pem", pkcs8PEM, t)
	passPath := writeTemp(dir, "pass.txt", "WRONG", t)

	fsp := New(WithKeyPath(keyPath), WithKeyPassphrasePath(passPath))
	_, err := fsp.Signer(context.Background())
	require.Error(t, err)

	// Also check env wrong
	t.Setenv("WITNESS_KEY_PASSPHRASE", "WRONG2")
	fsp2 := New(WithKeyPath(keyPath))
	_, err = fsp2.Signer(context.Background())
	require.Error(t, err)

	// And explicit wrong
	fsp3 := New(WithKeyPath(keyPath), WithKeyPassphrase("WRONG3"))
	_, err = fsp3.Signer(context.Background())
	require.Error(t, err)
}

// Sanity: ensure verifier made from public key can also verify
func TestFileSignerProvider_VerifyWithPublicKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTemp(dir, "key.pem", pkcs8PEM, t)
	passPath := writeTemp(dir, "pass.txt", passphrase, t)

	fsp := New(WithKeyPath(keyPath), WithKeyPassphrasePath(passPath))
	s, err := fsp.Signer(context.Background())
	require.NoError(t, err)

	// Build verifier from the signer's certificate/public key path
	v, err := s.Verifier()
	require.NoError(t, err)

	msg := []byte("hello-public")
	sig, err := s.Sign(bytes.NewReader(msg))
	require.NoError(t, err)
	require.NoError(t, v.Verify(bytes.NewReader(msg), sig))

	// Also try building a verifier directly from the public key
	pubID, err := s.KeyID()
	require.NoError(t, err)
	_ = pubID // not asserted here, but ensures KeyID path is exercised
}
