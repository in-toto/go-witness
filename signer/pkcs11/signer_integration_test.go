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

//go:build integration && linux && !android && (amd64 || arm64)

package pkcs11

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/dsse"
	"github.com/stretchr/testify/require"
)

// The tests need SoftHSM v2 on the machine that runs them: the softhsm2-util
// command and libsofthsm2.so, which is loaded into the test process. On
// Debian and Ubuntu both come with the softhsm2 package. Set SOFTHSM2_MODULE
// if the module is somewhere else. Without SoftHSM the tests skip.
const (
	testTokenLabel = "go-witness test token"
	testPINEnv     = "WITNESS_TEST_PKCS11_PIN"
	testPIN        = "123456"
)

var (
	testModulePath string
	// skipReason is why the token tests cannot run; empty when SoftHSM is
	// installed.
	skipReason string
	// testKeys holds the software copies of the keys imported into the token,
	// by label.
	testKeys = map[string]*ecdsa.PrivateKey{}
)

// TestMain creates a SoftHSM token in a temporary directory for all tests.
// Without SoftHSM it creates nothing: the token tests skip and the other
// tests of the package still run.
func TestMain(m *testing.M) {
	if skipReason = findSoftHSM(); skipReason != "" {
		os.Exit(m.Run())
	}

	dir, err := os.MkdirTemp("", "witness-pkcs11")
	if err != nil {
		panic(err)
	}

	if err := setupToken(dir); err != nil {
		os.RemoveAll(dir)
		panic("failed to setup SoftHSM token: " + err.Error())
	}

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// findSoftHSM sets testModulePath, or returns what is missing.
func findSoftHSM() string {
	if _, err := exec.LookPath("softhsm2-util"); err != nil {
		return "softhsm2-util not found: install the softhsm2 package"
	}

	candidates := []string{
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
	}
	if path := os.Getenv("SOFTHSM2_MODULE"); path != "" {
		candidates = []string{path}
	}
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			testModulePath = path
			return ""
		}
	}

	return "libsofthsm2.so not found: install the softhsm2 package or set SOFTHSM2_MODULE"
}

func requireToken(t *testing.T) {
	t.Helper()
	if skipReason != "" {
		t.Skip(skipReason)
	}
}

func setupToken(dir string) error {
	conf := filepath.Join(dir, "softhsm2.conf")
	if err := os.Mkdir(filepath.Join(dir, "tokens"), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(conf, []byte("directories.tokendir = "+dir+"/tokens\nobjectstore.backend = file\n"), 0o600); err != nil {
		return err
	}
	// Both softhsm2-util and the module loaded into this process read it.
	os.Setenv("SOFTHSM2_CONF", conf)

	if err := softhsm2Util("--init-token", "--free", "--label", testTokenLabel, "--pin", testPIN, "--so-pin", "12345678"); err != nil {
		return err
	}

	// softhsm2-util imports PKCS#8 files, which also gives the tests the
	// public keys to compare with.
	for i, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384()} {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return err
		}

		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return err
		}

		label := curve.Params().Name
		keyFile := filepath.Join(dir, label+".pem")
		if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return err
		}

		if err := softhsm2Util("--import", keyFile, "--token", testTokenLabel, "--label", label, "--id", fmt.Sprintf("%02d", i+1), "--pin", testPIN); err != nil {
			return err
		}
		testKeys[label] = priv
	}

	return nil
}

func softhsm2Util(args ...string) error {
	out, err := exec.Command("softhsm2-util", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("softhsm2-util %v: %w: %s", args[0], err, out)
	}

	return nil
}

func newTestSigner(t *testing.T, keyLabel string) *Signer {
	t.Helper()
	requireToken(t)
	t.Setenv(testPINEnv, testPIN)
	sp := New(WithModulePath(testModulePath), WithTokenLabel(testTokenLabel), WithKeyLabel(keyLabel), WithPINEnv(testPINEnv))
	s, err := sp.Signer(context.Background())
	require.NoError(t, err)
	ps, ok := s.(*Signer)
	require.True(t, ok)
	t.Cleanup(func() { require.NoError(t, ps.Close()) })
	return ps
}

// Signers are opened and closed independently of each other, so closing one
// must not take the module away from the others. This is the first test that
// loads the module, so its goroutines also race for the first C_Initialize of
// the process.
func TestConcurrentSigners(t *testing.T) {
	requireToken(t)
	t.Setenv(testPINEnv, testPIN)
	sp := New(WithModulePath(testModulePath), WithTokenLabel(testTokenLabel), WithKeyLabel("P-256"), WithPINEnv(testPINEnv))

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			for range 10 {
				s, err := sp.Signer(context.Background())
				if err != nil {
					errs <- err
					return
				}

				_, err = s.Sign(strings.NewReader("message"))
				if closeErr := s.(*Signer).Close(); err == nil {
					err = closeErr
				}
				if err != nil {
					errs <- err
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
}

// The acceptance test of the provider: what it signs verifies with the public
// key read from the token and with the public key file a policy would hold.
func TestSignAndVerify(t *testing.T) {
	requireToken(t)
	for label, priv := range testKeys {
		t.Run(label, func(t *testing.T) {
			s := newTestSigner(t, label)
			require.True(t, s.pub.Equal(&priv.PublicKey), "public key read from the token differs from the imported one")

			// A verifier made from the public key file is what a policy and
			// `witness verify -k` use.
			pemBytes, err := cryptoutil.PublicPemBytes(&priv.PublicKey)
			require.NoError(t, err)
			verifier, err := cryptoutil.NewVerifierFromReader(bytes.NewReader(pemBytes))
			require.NoError(t, err)
			wantID, err := verifier.KeyID()
			require.NoError(t, err)
			id, err := s.KeyID()
			require.NoError(t, err)
			require.Equal(t, wantID, id)

			msg := strings.Repeat("message ", 10000)
			sig, err := s.Sign(strings.NewReader(msg))
			require.NoError(t, err)
			require.NoError(t, verifier.Verify(strings.NewReader(msg), sig))
			require.Error(t, verifier.Verify(strings.NewReader("another message"), sig))

			env, err := dsse.Sign("application/vnd.in-toto+json", strings.NewReader(`{"a":1}`), dsse.SignWithSigners(s))
			require.NoError(t, err)
			require.Equal(t, wantID, env.Signatures[0].KeyID)
			fromToken, err := s.Verifier()
			require.NoError(t, err)
			for _, v := range []cryptoutil.Verifier{fromToken, verifier} {
				_, err = env.Verify(dsse.VerifyWithVerifiers(v))
				require.NoError(t, err)
			}
		})
	}
}

// One signer is used for several signatures in a run, possibly from several
// goroutines.
func TestConcurrentSign(t *testing.T) {
	s := newTestSigner(t, "P-256")
	verifier, err := s.Verifier()
	require.NoError(t, err)

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for g := range 8 {
		wg.Go(func() {
			for i := range 25 {
				msg := fmt.Sprintf("goroutine %d message %d", g, i)
				sig, err := s.Sign(strings.NewReader(msg))
				if err == nil {
					err = verifier.Verify(strings.NewReader(msg), sig)
				}
				if err != nil {
					errs <- err
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
}

// A second signer finds the module initialized and the token logged in, and
// goes on working when the first one is closed.
func TestTwoSigners(t *testing.T) {
	first := newTestSigner(t, "P-256")
	second := newTestSigner(t, "P-384")
	for _, s := range []*Signer{first, second, first} {
		_, err := s.Sign(strings.NewReader("message"))
		require.NoError(t, err)
	}

	require.NoError(t, first.Close())
	_, err := first.Sign(strings.NewReader("message"))
	require.ErrorContains(t, err, "signer is closed")
	_, err = second.Sign(strings.NewReader("message"))
	require.NoError(t, err)
}

func TestSignerErrors(t *testing.T) {
	requireToken(t)
	tests := []struct {
		name    string
		module  string
		token   string
		key     string
		pin     string
		wantErr string
	}{
		{"unknown token", testModulePath, "no such token", "P-256", testPIN, `no token with label "no such token"`},
		{"unknown key", testModulePath, testTokenLabel, "no such key", testPIN, `private key with label "no such key": not found`},
		// After "unknown key", which fails after a successful login: a session
		// left open by that attempt would keep the token logged in and the
		// wrong PIN would be accepted.
		{"wrong pin", testModulePath, testTokenLabel, "P-256", "654321", "C_Login: CKR_PIN_INCORRECT"},
		{"missing module", "/nonexistent/module.so", testTokenLabel, "P-256", testPIN, "load module"},
		// Any shared library without C_GetFunctionList will do; the dynamic
		// loader finds libm by its name.
		{"not a PKCS#11 module", "libm.so.6", testTokenLabel, "P-256", testPIN, "is not a PKCS#11 module"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(testPINEnv, tt.pin)
			sp := New(WithModulePath(tt.module), WithTokenLabel(tt.token), WithKeyLabel(tt.key), WithPINEnv(testPINEnv))
			_, err := sp.Signer(context.Background())
			require.ErrorContains(t, err, "pkcs11: ")
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
