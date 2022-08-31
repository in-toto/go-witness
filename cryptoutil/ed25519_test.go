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

package cryptoutil

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	ed25519pub = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAVpmcpVl2C/HQukPSQCZWPJDzhcg7OTc7NibX2vSCRqI=
-----END PUBLIC KEY-----`
	ed25519priv = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPigCK3/yyPwylOxDgyM2rg2QIK18kmoVeBBjpYiQaRB
-----END PRIVATE KEY-----`
)

func TestEd25519KeyID(t *testing.T) {
	signer, err := NewSignerFromReader(bytes.NewReader([]byte(ed25519priv)))
	require.NoError(t, err)
	assert.IsType(t, &ED25519Signer{}, signer)
	verifier, err := NewVerifierFromReader(bytes.NewReader([]byte(ed25519pub)))
	require.NoError(t, err)
	assert.IsType(t, &ED25519Verifier{}, verifier)
	signerID, err := signer.KeyID()
	require.NoError(t, err)
	verifierID, err := verifier.KeyID()
	require.NoError(t, err)
	assert.Equal(t, signerID, verifierID)
}
