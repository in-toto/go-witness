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
