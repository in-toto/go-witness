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

//go:build linux && !android && (amd64 || arm64)

package pkcs11

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

// session signs with one private key over one session.
type session struct {
	mod    *module
	sigLen int

	// A session carries one sign operation at a time, so C_SignInit and
	// C_Sign run as a pair under mu.
	mu     sync.Mutex
	handle ckULong
	key    ckULong
	closed bool
}

// initMu serializes C_Initialize. The locking that CKF_OS_LOCKING_OK asks of
// the module is set up by that very call, so two signers that are created at
// the same time must not be inside it together.
var initMu sync.Mutex

// openToken does the work of PKCS11SignerProvider.Signer on the platforms the
// module loader covers.
func openToken(modulePath, tokenLabel, keyLabel string, pin []byte) (token, *ecdsa.PublicKey, error) {
	mod, err := load(modulePath)
	if err != nil {
		return nil, nil, err
	}

	// Calls from Go reach the module on arbitrary OS threads, so the module
	// has to do its own locking. Another signer in the process may have
	// initialized the module already.
	initMu.Lock()
	rv := mod.initialize(&ckCInitializeArgs{flags: ckfOSLockingOK})
	initMu.Unlock()
	if rv != ckrOK && rv != ckrCryptokiAlreadyInitialized {
		return nil, nil, &ckError{"C_Initialize", uint(rv)}
	}

	s := &session{mod: mod}
	pub, err := s.setup(tokenLabel, keyLabel, pin)
	if err != nil {
		_ = s.close()
		return nil, nil, err
	}

	s.sigLen = rawSignatureLen(pub.Curve)
	return s, pub, nil
}

func (s *session) setup(tokenLabel, keyLabel string, pin []byte) (*ecdsa.PublicKey, error) {
	slot, err := s.mod.findSlot(tokenLabel)
	if err != nil {
		return nil, err
	}

	if rv := s.mod.openSession(slot, ckfSerialSession, nil, 0, &s.handle); rv != ckrOK {
		return nil, &ckError{"C_OpenSession", uint(rv)}
	}

	// Login state is shared by all sessions of the process with this token.
	rv := s.mod.login(s.handle, ckuUser, unsafe.SliceData(pin), ckULong(len(pin)))
	if rv != ckrOK && rv != ckrUserAlreadyLoggedIn {
		return nil, &ckError{"C_Login", uint(rv)}
	}

	if s.key, err = s.mod.findObject(s.handle, ckoPrivateKey, ckaLabel, []byte(keyLabel)); err != nil {
		return nil, fmt.Errorf("private key with label %q: %w", keyLabel, err)
	}

	// CKA_EC_POINT exists only on the public key object. The two halves of a
	// key pair share their CKA_ID, while a label may also be on the public key
	// of another pair, so the public key is looked up by the ID. Only a
	// private key without an ID is paired by label.
	id, err := s.mod.attribute(s.handle, s.key, ckaID)
	if err != nil {
		return nil, fmt.Errorf("CKA_ID of the private key: %w", err)
	}

	var pub ckULong
	if len(id) > 0 {
		pub, err = s.mod.findObject(s.handle, ckoPublicKey, ckaID, id)
	} else {
		pub, err = s.mod.findObject(s.handle, ckoPublicKey, ckaLabel, []byte(keyLabel))
	}
	if err != nil {
		return nil, fmt.Errorf("public key of private key %q: %w", keyLabel, err)
	}

	params, err := s.mod.attribute(s.handle, pub, ckaECParams)
	if err != nil {
		return nil, fmt.Errorf("CKA_EC_PARAMS: %w", err)
	}

	point, err := s.mod.attribute(s.handle, pub, ckaECPoint)
	if err != nil {
		return nil, fmt.Errorf("CKA_EC_POINT: %w", err)
	}

	return parsePublicKey(params, point)
}

func (s *session) signDigest(digest []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("signer is closed")
	}

	if rv := s.mod.signInit(s.handle, &ckMechanism{mechanism: ckmECDSA}, s.key); rv != ckrOK {
		return nil, &ckError{"C_SignInit", uint(rv)}
	}

	// CKM_ECDSA output is always r||s at twice the order length, so the
	// length query is skipped. Any C_Sign failure other than
	// CKR_BUFFER_TOO_SMALL ends the operation.
	raw := make([]byte, s.sigLen)
	n := ckULong(len(raw))
	if rv := s.mod.sign(s.handle, unsafe.SliceData(digest), ckULong(len(digest)), unsafe.SliceData(raw), &n); rv != ckrOK {
		return nil, &ckError{"C_Sign", uint(rv)}
	}

	if n != ckULong(len(raw)) {
		return nil, fmt.Errorf("C_Sign returned %d bytes, want %d", n, len(raw))
	}

	return raw, nil
}

// close ends the session. Closing the last session with the token also logs
// out. C_Finalize is never called: the module is initialized once for the
// whole process, other signers may still use it, and cryptoutil.Signer has no
// Close from which to tell that the last one is done.
func (s *session) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}

	s.closed = true
	// The handle is zero when setup failed before a session was opened.
	if s.handle != 0 {
		if rv := s.mod.closeSession(s.handle); rv != ckrOK {
			return &ckError{"C_CloseSession", uint(rv)}
		}
	}

	return nil
}
