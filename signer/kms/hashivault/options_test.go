// Copyright 2026 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hashivault

import (
	"testing"

	"github.com/in-toto/go-witness/signer"
	"github.com/in-toto/go-witness/signer/kms"
	"github.com/stretchr/testify/require"
)

// TestDefaultClientOptions ensures the provider-specific client options expose
// the expected defaults for the transit engine path and the kubernetes SA token path
// when creating a new signer via NewSignerProvider.
func TestDefaultClientOptions(t *testing.T) {
	sp, err := signer.NewSignerProvider("kms")
	require.NoError(t, err)

	ksp, ok := sp.(*kms.KMSSignerProvider)
	require.True(t, ok)

	// providerName and clientOptions are package-local to hashivault
	coIface, ok := ksp.Options[providerName]
	require.True(t, ok)

	co, ok := coIface.(*clientOptions)
	require.True(t, ok)

	require.Equal(t, defaultTransitSecretEnginePath, co.transitSecretEnginePath)
	require.Equal(t, defaultKubernetesSATokenPath, co.kubernetesSaTokenPath)
}
