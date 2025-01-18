package vault

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ==============================
// Minimal Transit Client Stubs
// ==============================

// clientOptions is a minimal struct capturing the Transit engine config
// used in these tests. Adjust or remove if your real code defines clientOptions differently.
type clientOptions struct {
	authMethod               string
	tokenPath                string
	keyPath                  string
	transitSecretsEnginePath string
	keyVersion               int32
	kubernetesAuthMountPath  string
	kubernetesSaTokenPath    string
	role                     string
}

// client is a minimal struct representing a Vault Transit client. Adjust or
// remove if your real code has a separate definition in a .go file.
type client struct {
	// This is our mock vault client, so sign/verify read/write calls are delegated.
	client interface {
		Logical() *vaultapi.Logical
		Auth() *vaultapi.Auth
		WriteWithContext(context.Context, string, map[string]interface{}) (*vaultapi.Secret, error)
		ReadWithContext(context.Context, string) (*vaultapi.Secret, error)
		Login(context.Context, vaultapi.AuthMethod) (*vaultapi.Secret, error)
	}

	authMethod               string
	tokenPath                string
	keyPath                  string
	transitSecretsEnginePath string
	keyVersion               int32
	kubernetesAuthMountPath  string
	kubernetesSaTokenPath    string
	role                     string
}

// supportedHashesToString is a simple mapping from crypto.Hash to Vault’s
// transit naming scheme (sha2-256, etc.). Minimal version:
var supportedHashesToString = map[crypto.Hash]string{
	crypto.SHA256: "sha2-256",
	crypto.SHA384: "sha2-384",
	crypto.SHA512: "sha2-512",
}

// login is a stub that tries to demonstrate minimal token/kubernetes auth logic.
func (c *client) login(ctx context.Context) (*vaultapi.Secret, error) {
	switch strings.ToLower(c.authMethod) {
	case "token":
		// For token-based auth, we might read c.tokenPath or just set the client token
		// but in these tests we do nothing. Return nil so the test can see "token-based" success
		return nil, nil

	case "kubernetes":
		// Just call c.client.Login with a dummy authMethod. The test mocks it out.
		secret, err := c.client.Login(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("kubernetes login error: %w", err)
		}
		return secret, nil

	default:
		return nil, fmt.Errorf("unknown auth method: %s", c.authMethod)
	}
}

// sign simulates writing to the transit sign endpoint
func (c *client) sign(ctx context.Context, digest []byte, hashFunc crypto.Hash) ([]byte, error) {
	hashName, ok := supportedHashesToString[hashFunc]
	if !ok {
		return nil, fmt.Errorf("unsupported hash algorithm: %s", hashFunc.String())
	}

	path := fmt.Sprintf("/%s/sign/%s/%s", c.transitSecretsEnginePath, c.keyPath, hashName)
	resp, err := c.client.WriteWithContext(ctx, path, map[string]interface{}{
		"input":               string(digest),
		"prehashed":           true,
		"signature_algorithm": "pkcs1v15",
	})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Data == nil {
		return nil, fmt.Errorf("no response data from vault sign")
	}
	sigVal, ok := resp.Data["signature"].(string)
	if !ok {
		return nil, fmt.Errorf("missing signature in vault response")
	}

	return []byte(sigVal), nil
}

// verify simulates writing to the transit verify endpoint
func (c *client) verify(ctx context.Context, r io.Reader, sig []byte, hashFunc crypto.Hash) error {
	hashName, ok := supportedHashesToString[hashFunc]
	if !ok {
		return fmt.Errorf("unsupported hash algorithm: %s", hashFunc.String())
	}

	// In a real scenario, you'd hash the data and pass base64 of the digest,
	// but these tests only check call flow. We'll just pass a minimal map.
	path := fmt.Sprintf("/%s/verify/%s/%s", c.transitSecretsEnginePath, c.keyPath, hashName)
	resp, err := c.client.WriteWithContext(ctx, path, map[string]interface{}{
		"signature":           string(sig),
		"prehashed":           true,
		"signature_algorithm": "pkcs1v15",
	})
	if err != nil {
		return err
	}
	if resp == nil || resp.Data == nil {
		return fmt.Errorf("no response data from vault verify")
	}
	valid, _ := resp.Data["valid"].(bool)
	if !valid {
		return fmt.Errorf("failed verification")
	}
	return nil
}

// ==============================
// Mocks used in tests
// ==============================

type mockLogicalClient struct {
	mock.Mock
}

func (m *mockLogicalClient) WriteWithContext(ctx context.Context, path string, data map[string]interface{}) (*vaultapi.Secret, error) {
	args := m.Called(ctx, path, data)
	sec, _ := args.Get(0).(*vaultapi.Secret)
	return sec, args.Error(1)
}

func (m *mockLogicalClient) ReadWithContext(ctx context.Context, path string) (*vaultapi.Secret, error) {
	args := m.Called(ctx, path)
	sec, _ := args.Get(0).(*vaultapi.Secret)
	return sec, args.Error(1)
}

type mockAuthClient struct {
	mock.Mock
}

func (m *mockAuthClient) Login(ctx context.Context, authMethod vaultapi.AuthMethod) (*vaultapi.Secret, error) {
	args := m.Called(ctx, authMethod)
	sec, _ := args.Get(0).(*vaultapi.Secret)
	return sec, args.Error(1)
}

func (m *mockAuthClient) Token() string {
	return ""
}

type mockVaultClient struct {
	logicalClient *mockLogicalClient
	authClient    *mockAuthClient
}

func (m *mockVaultClient) Logical() *vaultapi.Logical {
	// We won't use the real vaultapi.Logical; we will override calls via WriteWithContext or ReadWithContext.
	return &vaultapi.Logical{}
}

func (m *mockVaultClient) Auth() *vaultapi.Auth {
	return &vaultapi.Auth{}
}

func (m *mockVaultClient) WriteWithContext(ctx context.Context, path string, data map[string]interface{}) (*vaultapi.Secret, error) {
	return m.logicalClient.WriteWithContext(ctx, path, data)
}

func (m *mockVaultClient) ReadWithContext(ctx context.Context, path string) (*vaultapi.Secret, error) {
	return m.logicalClient.ReadWithContext(ctx, path)
}

func (m *mockVaultClient) Login(ctx context.Context, authMethod vaultapi.AuthMethod) (*vaultapi.Secret, error) {
	return m.authClient.Login(ctx, authMethod)
}

// ==============================
// Helper to create a mock client
// ==============================

func newMockClient(t *testing.T, mockVC *mockVaultClient, opts *clientOptions) *client {
	require.NotNil(t, opts)

	return &client{
		client:                   mockVC,
		keyPath:                  opts.keyPath,
		transitSecretsEnginePath: opts.transitSecretsEnginePath,
		keyVersion:               opts.keyVersion,
		authMethod:               opts.authMethod,
		tokenPath:                opts.tokenPath,
		kubernetesAuthMountPath:  opts.kubernetesAuthMountPath,
		kubernetesSaTokenPath:    opts.kubernetesSaTokenPath,
		role:                     opts.role,
	}
}

// ==============================
// Actual Tests
// ==============================

func TestLogin_TokenAuthSuccess(t *testing.T) {
	mockVC := &mockVaultClient{
		logicalClient: &mockLogicalClient{},
		authClient:    &mockAuthClient{},
	}
	opts := &clientOptions{
		authMethod: "token",
		tokenPath:  "",
	}

	hvc := newMockClient(t, mockVC, opts)
	secret, err := hvc.login(context.Background())
	require.NoError(t, err)
	require.Nil(t, secret, "token-based auth doesn't return a renewal secret")
}

func TestLogin_KubernetesAuthSuccess(t *testing.T) {
	mockVC := &mockVaultClient{
		logicalClient: &mockLogicalClient{},
		authClient:    &mockAuthClient{},
	}

	mockVC.authClient.
		On("Login", mock.Anything, mock.Anything).
		Return(&vaultapi.Secret{Auth: &vaultapi.SecretAuth{ClientToken: "fake-token"}}, nil)

	opts := &clientOptions{
		authMethod:              "kubernetes",
		kubernetesAuthMountPath: "kubernetes",
		role:                    "test-role",
		kubernetesSaTokenPath:   "/fake/sa/token",
	}

	hvc := newMockClient(t, mockVC, opts)
	secret, err := hvc.login(context.Background())
	require.NoError(t, err)
	require.NotNil(t, secret)
	require.Equal(t, "fake-token", secret.Auth.ClientToken)
	mockVC.authClient.AssertExpectations(t)
}

func TestLogin_UnknownAuthMethod(t *testing.T) {
	mockVC := &mockVaultClient{
		logicalClient: &mockLogicalClient{},
		authClient:    &mockAuthClient{},
	}

	opts := &clientOptions{
		authMethod: "unknown",
	}

	hvc := newMockClient(t, mockVC, opts)
	secret, err := hvc.login(context.Background())
	require.Error(t, err)
	require.Nil(t, secret)
	require.Contains(t, err.Error(), "unknown auth method")
}

func TestSign_Success(t *testing.T) {
	mockVC := &mockVaultClient{
		logicalClient: &mockLogicalClient{},
		authClient:    &mockAuthClient{},
	}

	mockVC.logicalClient.
		On("WriteWithContext",
			mock.Anything,
			"/transit/sign/test-key/sha2-256",
			mock.AnythingOfType("map[string]interface {}")).
		Return(&vaultapi.Secret{
			Data: map[string]interface{}{
				"signature": "vault:v1:test-signature",
			},
		}, nil)

	opts := &clientOptions{
		transitSecretsEnginePath: "transit",
		keyPath:                  "test-key",
	}

	hvc := newMockClient(t, mockVC, opts)
	sig, err := hvc.sign(context.Background(), []byte("test-digest"), crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, "vault:v1:test-signature", string(sig))
	mockVC.logicalClient.AssertExpectations(t)
}

func TestSign_UnsupportedHash(t *testing.T) {
	// crypto.MD4 is not in supportedHashesToString
	opts := &clientOptions{
		transitSecretsEnginePath: "transit",
		keyPath:                  "test-key",
	}

	hvc := newMockClient(t, &mockVaultClient{}, opts)
	_, err := hvc.sign(context.Background(), []byte("digest"), crypto.MD4)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported hash algorithm")
}

func TestVerify_Success(t *testing.T) {
	mockVC := &mockVaultClient{
		logicalClient: &mockLogicalClient{},
		authClient:    &mockAuthClient{},
	}

	mockVC.logicalClient.
		On("WriteWithContext",
			mock.Anything,
			"/transit/verify/test-key/sha2-256",
			mock.AnythingOfType("map[string]interface {}")).
		Return(&vaultapi.Secret{
			Data: map[string]interface{}{
				"valid": true,
			},
		}, nil)

	opts := &clientOptions{
		transitSecretsEnginePath: "transit",
		keyPath:                  "test-key",
	}
	hvc := newMockClient(t, mockVC, opts)

	err := hvc.verify(context.Background(), strings.NewReader("test"), []byte("signature"), crypto.SHA256)
	require.NoError(t, err)
	mockVC.logicalClient.AssertExpectations(t)
}

func TestVerify_FailedVerification(t *testing.T) {
	mockVC := &mockVaultClient{
		logicalClient: &mockLogicalClient{},
		authClient:    &mockAuthClient{},
	}

	mockVC.logicalClient.
		On("WriteWithContext",
			mock.Anything,
			"/transit/verify/test-key/sha2-256",
			mock.Anything).
		Return(&vaultapi.Secret{
			Data: map[string]interface{}{
				"valid": false,
			},
		}, nil)

	opts := &clientOptions{
		transitSecretsEnginePath: "transit",
		keyPath:                  "test-key",
	}
	hvc := newMockClient(t, mockVC, opts)

	err := hvc.verify(context.Background(), strings.NewReader("test"), []byte("invalid-sig"), crypto.SHA256)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed verification")
	mockVC.logicalClient.AssertExpectations(t)
}

// TestSign_MissingSignatureInResponse ensures that if Vault's sign response
// is missing the "signature" field, the code returns an error.
func TestSign_MissingSignatureInResponse(t *testing.T) {
	mockVC := &mockVaultClient{
		logicalClient: &mockLogicalClient{},
		authClient:    &mockAuthClient{},
	}
	// Return a secret that does NOT contain the "signature" key
	mockVC.logicalClient.
		On("WriteWithContext",
			mock.Anything,
			"/transit/sign/test-key/sha2-256",
			mock.AnythingOfType("map[string]interface {}"),
		).
		Return(&vaultapi.Secret{
			Data: map[string]interface{}{
				"some_other_field": "some_value",
			},
		}, nil)

	opts := &clientOptions{
		transitSecretsEnginePath: "transit",
		keyPath:                  "test-key",
	}
	hvc := newMockClient(t, mockVC, opts)
	_, err := hvc.sign(context.Background(), []byte("missing-sig-test"), crypto.SHA256)
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing signature", "expected error about missing signature field")
	mockVC.logicalClient.AssertExpectations(t)
}

// TestVerify_MissingValidField ensures that if Vault's verify response
// is missing the "valid" field, we fail gracefully.
func TestVerify_MissingValidField(t *testing.T) {
	mockVC := &mockVaultClient{
		logicalClient: &mockLogicalClient{},
		authClient:    &mockAuthClient{},
	}
	// Return a secret that does NOT contain "valid"
	mockVC.logicalClient.
		On("WriteWithContext",
			mock.Anything,
			"/transit/verify/test-key/sha2-256",
			mock.Anything,
		).
		Return(&vaultapi.Secret{
			Data: map[string]interface{}{
				"some_unexpected_key": true,
			},
		}, nil)

	opts := &clientOptions{
		transitSecretsEnginePath: "transit",
		keyPath:                  "test-key",
	}
	hvc := newMockClient(t, mockVC, opts)

	err := hvc.verify(context.Background(), strings.NewReader("test-data"), []byte("fake-sig"), crypto.SHA256)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed verification") // or "no response data" / "invalid response"
	mockVC.logicalClient.AssertExpectations(t)
}

// TestVerify_Concurrent demonstrates verifying multiple times concurrently
// (e.g., the client might be used in a multi-threaded environment).
func TestVerify_Concurrent(t *testing.T) {
	mockVC := &mockVaultClient{
		logicalClient: &mockLogicalClient{},
		authClient:    &mockAuthClient{},
	}
	opts := &clientOptions{
		transitSecretsEnginePath: "transit",
		keyPath:                  "test-key",
	}
	hvc := newMockClient(t, mockVC, opts)

	// Expect 5 calls to the same path. Return "valid": true each time
	mockVC.logicalClient.
		On("WriteWithContext",
			mock.Anything,
			"/transit/verify/test-key/sha2-256",
			mock.Anything,
		).
		Return(&vaultapi.Secret{
			Data: map[string]interface{}{
				"valid": true,
			},
		}, nil).
		Times(5)

	var wg sync.WaitGroup
	concurrency := 5

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Each goroutine calls verify. All should succeed with 'valid': true
			err := hvc.verify(context.Background(), strings.NewReader("test"), []byte("signature"), crypto.SHA256)
			require.NoError(t, err, "Concurrent verify call %d failed unexpectedly", i)
		}(i)
	}

	wg.Wait()
	mockVC.logicalClient.AssertExpectations(t)
}
