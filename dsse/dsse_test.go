// Copyright 2022 The Witness Contributors
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

package dsse

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testifysec/go-witness/cryptoutil"
)

func createTestKey() (cryptoutil.Signer, cryptoutil.Verifier, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	signer := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
	verifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)
	if err != nil {
		return nil, nil, err
	}

	return signer, verifier, nil
}

func TestSign(t *testing.T) {
	signer, _, err := createTestKey()
	require.NoError(t, err)
	_, err = Sign("dummydata", bytes.NewReader([]byte("this is some dummy data")), signer)
	require.NoError(t, err)
}

func TestVerify(t *testing.T) {
	signer, verifier, err := createTestKey()
	require.NoError(t, err)
	env, err := Sign("dummydata", bytes.NewReader([]byte("this is some dummy data")), signer)
	require.NoError(t, err)
	approvedVerifiers, err := env.Verify(WithVerifiers([]cryptoutil.Verifier{verifier}))
	assert.ElementsMatch(t, approvedVerifiers, []cryptoutil.Verifier{verifier})
	require.NoError(t, err)
}

func TestFailVerify(t *testing.T) {
	signer, _, err := createTestKey()
	require.NoError(t, err)
	_, verifier, err := createTestKey()
	require.NoError(t, err)
	env, err := Sign("dummydata", bytes.NewReader([]byte("this is some dummy data")), signer)
	require.NoError(t, err)
	approvedVerifiers, err := env.Verify(WithVerifiers([]cryptoutil.Verifier{verifier}))
	assert.Empty(t, approvedVerifiers)
	require.ErrorIs(t, err, ErrNoMatchingSigs{})
}

func TestMultiSigners(t *testing.T) {
	signers := []cryptoutil.Signer{}
	verifiers := []cryptoutil.Verifier{}
	for i := 0; i < 5; i++ {
		s, v, err := createTestKey()
		require.NoError(t, err)
		signers = append(signers, s)
		verifiers = append(verifiers, v)
	}

	env, err := Sign("dummydata", bytes.NewReader([]byte("this is some dummy data")), signers...)
	require.NoError(t, err)

	approvedVerifiers, err := env.Verify(WithVerifiers(verifiers))
	require.NoError(t, err)
	assert.ElementsMatch(t, approvedVerifiers, verifiers)
}

func TestThreshold(t *testing.T) {
	signers := []cryptoutil.Signer{}
	expectedVerifiers := []cryptoutil.Verifier{}
	verifiers := []cryptoutil.Verifier{}
	for i := 0; i < 5; i++ {
		s, v, err := createTestKey()
		require.NoError(t, err)
		signers = append(signers, s)
		expectedVerifiers = append(expectedVerifiers, v)
		verifiers = append(verifiers, v)
	}

	// create some additional verifiers that won't be used to sign
	for i := 0; i < 5; i++ {
		_, v, err := createTestKey()
		require.NoError(t, err)
		verifiers = append(verifiers, v)
	}

	env, err := Sign("dummydata", bytes.NewReader([]byte("this is some dummy data")), signers...)
	require.NoError(t, err)

	approvedVerifiers, err := env.Verify(WithVerifiers(verifiers), WithThreshold(5))
	require.NoError(t, err)
	assert.ElementsMatch(t, approvedVerifiers, expectedVerifiers)

	approvedVerifiers, err = env.Verify(WithVerifiers(verifiers), WithThreshold(10))
	require.ErrorIs(t, err, ErrThresholdNotMet{Acutal: 5, Theshold: 10})
	assert.ElementsMatch(t, approvedVerifiers, expectedVerifiers)

	_, err = env.Verify(WithVerifiers(verifiers), WithThreshold(-10))
	require.ErrorIs(t, err, ErrInvalidThreshold(-10))
}
