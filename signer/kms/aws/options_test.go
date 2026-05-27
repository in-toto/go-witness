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

package aws

import (
	"testing"

	"github.com/in-toto/go-witness/signer"
	"github.com/in-toto/go-witness/signer/kms"
	"github.com/stretchr/testify/require"
)

// TestAWSClientOptionDefaults ensures the AWS client options default values are
// applied when creating a new KMS signer provider.
func TestAWSClientOptionDefaults(t *testing.T) {
	sp, err := signer.NewSignerProvider("kms")
	require.NoError(t, err)

	ksp, ok := sp.(*kms.KMSSignerProvider)
	require.True(t, ok)

	coIface, ok := ksp.Options[providerName]
	require.True(t, ok)

	co, ok := coIface.(*awsClientOptions)
	require.True(t, ok)

	require.Equal(t, true, co.verifyRemotely)
	require.Equal(t, false, co.insecureSkipVerify)
}
