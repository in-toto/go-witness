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

// Package pkcs11 provides a signer whose ECDSA private key (P-256 or P-384)
// stays on a PKCS#11 token such as an HSM or a smart card. It works on Linux,
// amd64 and arm64.
//
// The token's module is loaded with purego, so the package builds with
// CGO_ENABLED=0. A Linux binary that imports it is dynamically linked even
// then. It asks for the loader of glibc (of musl when it is built on a musl
// system) and does not start where that loader is missing: a binary built on
// Debian does not start on Alpine. That is why go-witness does not import
// this package by default.
//
// The module is native code that runs inside the process with all its rights.
// It is loaded, and its initializers run, before the package can tell whether
// it is a PKCS#11 module, and it is never unloaded. module-path is handed to
// dlopen as it is: a name without a slash is searched in the library path of
// the dynamic loader and a relative path is resolved against the working
// directory, so give the absolute path of a module you trust.
//
// Not supported: RSA keys, PKCS#11 URIs, certificates stored on the token,
// keys with CKA_ALWAYS_AUTHENTICATE, tokens with a protected authentication
// path, macOS and Windows, key generation, a verifier provider, and modules
// that answer C_Initialize with CKR_CANT_LOCK.
package pkcs11

import (
	"context"
	"fmt"
	"os"

	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/registry"
	"github.com/in-toto/go-witness/signer"
)

func init() {
	signer.Register("pkcs11", func() signer.SignerProvider { return New() },
		registry.StringConfigOption(
			"module-path",
			"Path to the PKCS#11 module (shared library) of the token",
			"",
			func(sp signer.SignerProvider, modulePath string) (signer.SignerProvider, error) {
				psp, ok := sp.(*PKCS11SignerProvider)
				if !ok {
					return sp, fmt.Errorf("provided signer provider is not a pkcs11 signer provider")
				}

				WithModulePath(modulePath)(psp)
				return psp, nil
			},
		),
		registry.StringConfigOption(
			"token-label",
			"Label of the token that holds the key",
			"",
			func(sp signer.SignerProvider, tokenLabel string) (signer.SignerProvider, error) {
				psp, ok := sp.(*PKCS11SignerProvider)
				if !ok {
					return sp, fmt.Errorf("provided signer provider is not a pkcs11 signer provider")
				}

				WithTokenLabel(tokenLabel)(psp)
				return psp, nil
			},
		),
		registry.StringConfigOption(
			"key-label",
			"Label (CKA_LABEL) of the ECDSA private key on the token",
			"",
			func(sp signer.SignerProvider, keyLabel string) (signer.SignerProvider, error) {
				psp, ok := sp.(*PKCS11SignerProvider)
				if !ok {
					return sp, fmt.Errorf("provided signer provider is not a pkcs11 signer provider")
				}

				WithKeyLabel(keyLabel)(psp)
				return psp, nil
			},
		),
		registry.StringConfigOption(
			"pin-env",
			"Name of the environment variable that holds the user PIN of the token. Pick a name the environment attestor obfuscates, for example one containing TOKEN, SECRET or PASSWORD",
			"",
			func(sp signer.SignerProvider, pinEnv string) (signer.SignerProvider, error) {
				psp, ok := sp.(*PKCS11SignerProvider)
				if !ok {
					return sp, fmt.Errorf("provided signer provider is not a pkcs11 signer provider")
				}

				WithPINEnv(pinEnv)(psp)
				return psp, nil
			},
		),
	)
}

type PKCS11SignerProvider struct {
	modulePath string
	tokenLabel string
	keyLabel   string
	pinEnv     string
}

type Option func(*PKCS11SignerProvider)

func WithModulePath(modulePath string) Option {
	return func(psp *PKCS11SignerProvider) {
		psp.modulePath = modulePath
	}
}

func WithTokenLabel(tokenLabel string) Option {
	return func(psp *PKCS11SignerProvider) {
		psp.tokenLabel = tokenLabel
	}
}

func WithKeyLabel(keyLabel string) Option {
	return func(psp *PKCS11SignerProvider) {
		psp.keyLabel = keyLabel
	}
}

// WithPINEnv sets the name of the environment variable the user PIN is read
// from. The PIN itself is never an option, so it does not end up in a command
// line or a configuration file. The variable is still visible to the
// environment attestor, which records its value in clear unless the name is
// on the attestor's list of sensitive keys: among them names that contain
// TOKEN, SECRET or PASSWORD, and the keys given to attestation.WithEnvCapturer
// (--env-add-sensitive-key in witness). The attested command inherits the
// variable as well.
func WithPINEnv(pinEnv string) Option {
	return func(psp *PKCS11SignerProvider) {
		psp.pinEnv = pinEnv
	}
}

func New(opts ...Option) *PKCS11SignerProvider {
	psp := PKCS11SignerProvider{}
	for _, opt := range opts {
		opt(&psp)
	}

	return &psp
}

// Signer loads the module, logs in to the token and looks up the key pair.
// The returned signer is a *Signer; it holds a session until it is closed.
func (psp *PKCS11SignerProvider) Signer(_ context.Context) (cryptoutil.Signer, error) {
	if len(psp.modulePath) == 0 {
		return nil, fmt.Errorf("module-path is a required option")
	}

	if len(psp.tokenLabel) == 0 {
		return nil, fmt.Errorf("token-label is a required option")
	}

	if len(psp.keyLabel) == 0 {
		return nil, fmt.Errorf("key-label is a required option")
	}

	if len(psp.pinEnv) == 0 {
		return nil, fmt.Errorf("pin-env is a required option")
	}

	// The name is not printed: a PIN typed in its place would end up in logs.
	pin := os.Getenv(psp.pinEnv)
	if len(pin) == 0 {
		return nil, fmt.Errorf("the environment variable named by pin-env is empty or not set")
	}

	tok, pub, err := openToken(psp.modulePath, psp.tokenLabel, psp.keyLabel, []byte(pin))
	if err != nil {
		return nil, fmt.Errorf("pkcs11: %w", err)
	}

	return &Signer{tok: tok, pub: pub}, nil
}
