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

//go:build !(linux && !android && (amd64 || arm64))

package pkcs11

import (
	"context"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnsupportedPlatform(t *testing.T) {
	const pinEnv = "WITNESS_TEST_PKCS11_PIN"
	t.Setenv(pinEnv, "1234")
	sp := New(WithModulePath("module.so"), WithTokenLabel("t"), WithKeyLabel("k"), WithPINEnv(pinEnv))
	_, err := sp.Signer(context.Background())
	require.EqualError(t, err, "pkcs11: not supported on "+runtime.GOOS+"/"+runtime.GOARCH)
}
