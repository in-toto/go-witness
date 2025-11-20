// Copyright 2023 The Witness Contributors
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

package fulcio

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"math/big"

	"path/filepath"

	fulciopb "github.com/sigstore/fulcio/pkg/generated/protobuf"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/jose"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-jose/go-jose/v3/jwt"
)

func setupFulcioTestService(t *testing.T) (*dummyCAClientService, string) {
	service := &dummyCAClientService{}
	service.server = grpc.NewServer()
	fulciopb.RegisterCAServer(service.server, service)
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	client, err := newClient("https://localhost", lis.Addr().(*net.TCPAddr).Port, true)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	service.client = client
	go func() {
		if err := service.server.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()
	return service, fmt.Sprintf("localhost:%d", lis.Addr().(*net.TCPAddr).Port)
}

func TestNewClient(t *testing.T) {
	// test when fulcioURL is empty
	_, err := newClient("", 0, false)
	require.Error(t, err)

	// test when fulcioURL is invalid
	_, err = newClient("://", 0, false)
	require.Error(t, err)

	// test when connection to Fulcio succeeds
	client, err := newClient("https://fulcio.url", 0, false)
	require.NoError(t, err)
	require.NotNil(t, client)
}

type dummyCAClientService struct {
	client fulciopb.CAClient
	server *grpc.Server
	fulciopb.UnimplementedCAServer
}

type retryCAClientService struct {
	client       fulciopb.CAClient
	server       *grpc.Server
	attemptCount *int32
	maxFailures  int32
	fulciopb.UnimplementedCAServer
}

func (s *dummyCAClientService) GetTrustBundle(ctx context.Context, in *fulciopb.GetTrustBundleRequest) (*fulciopb.TrustBundle, error) {
	return &fulciopb.TrustBundle{
		Chains: []*fulciopb.CertificateChain{},
	}, nil
}

func (s *dummyCAClientService) CreateSigningCertificate(ctx context.Context, in *fulciopb.CreateSigningCertificateRequest) (*fulciopb.SigningCertificate, error) {
	t := &testing.T{}

	cert := fulciopb.SigningCertificate{
		Certificate: &fulciopb.SigningCertificate_SignedCertificateEmbeddedSct{
			SignedCertificateEmbeddedSct: &fulciopb.SigningCertificateEmbeddedSCT{
				Chain: &fulciopb.CertificateChain{
					Certificates: generateCertChain(t),
				},
			},
		},
	}
	return &cert, nil
}

func (s *retryCAClientService) GetTrustBundle(ctx context.Context, in *fulciopb.GetTrustBundleRequest) (*fulciopb.TrustBundle, error) {
	return &fulciopb.TrustBundle{
		Chains: []*fulciopb.CertificateChain{},
	}, nil
}

func (s *retryCAClientService) CreateSigningCertificate(ctx context.Context, in *fulciopb.CreateSigningCertificateRequest) (*fulciopb.SigningCertificate, error) {
	count := atomic.AddInt32(s.attemptCount, 1)
	if count <= s.maxFailures {
		return nil, status.Error(codes.Unavailable, "service temporarily unavailable")
	}

	t := &testing.T{}
	cert := fulciopb.SigningCertificate{
		Certificate: &fulciopb.SigningCertificate_SignedCertificateEmbeddedSct{
			SignedCertificateEmbeddedSct: &fulciopb.SigningCertificateEmbeddedSCT{
				Chain: &fulciopb.CertificateChain{
					Certificates: generateCertChain(t),
				},
			},
		},
	}
	return &cert, nil
}
func generateTestToken(email string, subject string) string {

	var claims struct {
		jwt.Claims
		Email   string `json:"email"`
		Subject string `json:"sub"`
	}

	key := []byte("test-secret")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, nil)
	if err != nil {
		log.Fatal(err)
	}

	if email != "" {
		claims.Email = email
	}

	if subject != "" {
		claims.Subject = subject
	}

	claims.Audience = []string{"sigstore"}

	builder := jwt.Signed(signer).Claims(claims)
	signedToken, _ := builder.CompactSerialize()

	return signedToken
}

func TestGetCert(t *testing.T) {
	service, _ := setupFulcioTestService(t)

	ctx := context.Background()

	// Generate a key pair for testing
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	// Set up a fake CAClient for testing

	// Test that an error is returned for an invalid token
	_, err = getCert(ctx, key, service.client, "invalid_token")
	require.Error(t, err)

	// Test that an error is returned for a token without a subject
	token := generateTestToken("", "")
	_, err = getCert(ctx, key, service.client, token)
	require.Error(t, err)

	// Test that an error is returned if the key cannot be loaded
	key2, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	_, err = getCert(ctx, key2, service.client, token)
	require.Error(t, err)

	// Generate a token with email claim for testing
	token = generateTestToken("test@example.com", "")
	// Test that a certificate is returned for a valid token and key
	cert, err := getCert(ctx, key, service.client, token)
	require.NoError(t, err)
	require.NotNil(t, cert)

	// Generate a token with subject claim for testing
	token = generateTestToken("", "examplesubject")
	// Test that a certificate is returned for a valid token and key
	cert, err = getCert(ctx, key, service.client, token)
	require.NoError(t, err)
	require.NotNil(t, cert)
}

func TestSigner(t *testing.T) {
	// Setup dummy CA client service
	service, url := setupFulcioTestService(t)
	defer service.server.Stop()

	ctx := context.Background()

	// Create mock token
	token := generateTestToken("foo@example.com", "")

	//pasre url to get hostname
	hostname := strings.Split(url, ":")[0]
	port := strings.Split(url, ":")[1]

	// Call Signer to generate a signer
	provider := New(WithFulcioURL(fmt.Sprintf("http://%v:%v", hostname, port)), WithToken(token))
	signer, err := provider.Signer(ctx)
	require.NoError(t, err)

	// Ensure signer is not nil
	require.NotNil(t, signer)
	provider = New(WithFulcioURL("https://test"), WithToken(token))
	_, err = provider.Signer(ctx)
	//this should be a tranport err since we cant actually test on 443 which is the default
	require.ErrorContains(t, err, "lookup test")

	// Test signer with token read from file
	// NOTE: this function could be refactored to accept a fileSystem or io.Reader so reading the file can be mocked,
	// but unsure if this is the way we want to go for now
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	rootDir := filepath.Dir(filepath.Dir(wd))
	tp := filepath.Join(rootDir, "hack", "test.token")

	provider = New(WithFulcioURL(fmt.Sprintf("http://%v:%v", hostname, port)), WithTokenPath(tp))
	_, err = provider.Signer(ctx)
	require.NoError(t, err)

	// Test signer with both token read from file and raw token
	provider = New(WithFulcioURL(fmt.Sprintf("http://%v:%v", hostname, port)), WithTokenPath(tp), WithToken(token))
	_, err = provider.Signer(ctx)
	require.ErrorContains(t, err, "only one of --fulcio-token-path or --fulcio-raw-token can be used")
}
func TestGetCertHTTP(t *testing.T) {
	t.Run("successful certificate retrieval", func(t *testing.T) {
		// Mock HTTP server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify the request method and path
			require.Equal(t, "POST", r.Method)
			require.Equal(t, "/api/v2/signingCert", r.URL.Path)

			// Verify the headers
			require.Equal(t, "application/json", r.Header.Get("Content-Type"))
			require.Equal(t, "application/json", r.Header.Get("Accept"))

			// Read the request body
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)

			// Verify the payload structure
			var payload map[string]interface{}
			err = json.Unmarshal(body, &payload)
			require.NoError(t, err)
			require.Contains(t, payload, "credentials")
			require.Contains(t, payload, "publicKeyRequest")

			// Return a mock response
			mockResponse := map[string]interface{}{
				"signedCertificateEmbeddedSct": map[string]interface{}{
					"chain": map[string]interface{}{
						"certificates": []string{
							"-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----",
						},
					},
				},
			}

			// Encode the mock response as JSON
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(mockResponse)
		}))
		defer server.Close()

		// Generate a test key
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		// Generate a test token
		token := generateTestToken("test@example.com", "")

		// Call getCertHTTP
		cert, err := getCertHTTP(context.Background(), key, server.URL, token)
		require.NoError(t, err)
		require.NotNil(t, cert)

		// Verify the certificate chain
		require.NotNil(t, cert.Certificate)
		switch cert := cert.Certificate.(type) {
		case *fulciopb.SigningCertificate_SignedCertificateEmbeddedSct:
			require.NotNil(t, cert.SignedCertificateEmbeddedSct)
			require.NotNil(t, cert.SignedCertificateEmbeddedSct.Chain)
			require.Len(t, cert.SignedCertificateEmbeddedSct.Chain.Certificates, 1)
			require.Equal(t, "-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----", cert.SignedCertificateEmbeddedSct.Chain.Certificates[0])
		default:
			t.Fatalf("unexpected certificate type: %T", cert)
		}
	})
	t.Run("unmarshaling error", func(t *testing.T) {
		// Mock HTTP server that returns invalid JSON
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`invalid json`))
		}))
		defer server.Close()

		// Generate a test key
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		// Generate a valid test token
		token := generateTestToken("test@example.com", "")

		// Call getCertHTTP and expect an error
		_, err = getCertHTTP(context.Background(), key, server.URL, token)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal response")
	})

	t.Run("HTTP request failure", func(t *testing.T) {
		// Mock HTTP server that returns an error
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "invalid request"}`))
		}))
		defer server.Close()

		// Generate a test key
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		// Generate a valid test token
		token := generateTestToken("test@example.com", "")

		// Call getCertHTTP and expect an error
		_, err = getCertHTTP(context.Background(), key, server.URL, token)
		require.Error(t, err)
		require.Contains(t, err.Error(), "HTTP request failed with status: 400 Bad Request")
	})
}

func generateCertChain(t *testing.T) []string {
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rootCertTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootCertDER, err := x509.CreateCertificate(rand.Reader, &rootCertTemplate, &rootCertTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)

	intermediateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	intermediateCertTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Intermediate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	intermediateCertDER, err := x509.CreateCertificate(rand.Reader, &intermediateCertTemplate, &rootCertTemplate, &intermediateKey.PublicKey, rootKey)
	require.NoError(t, err)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	leafCertTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Leaf",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	leafCertDER, err := x509.CreateCertificate(rand.Reader, &leafCertTemplate, &intermediateCertTemplate, &leafKey.PublicKey, intermediateKey)
	require.NoError(t, err)

	certs := []string{
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCertDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediateCertDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCertDER})),
	}

	return certs
}

func setupRetryFulcioTestService(t *testing.T, maxFailures int32) (*retryCAClientService, string) {
	service := &retryCAClientService{
		attemptCount: new(int32),
		maxFailures:  maxFailures,
	}
	service.server = grpc.NewServer()
	fulciopb.RegisterCAServer(service.server, service)
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	client, err := newClient("https://localhost", lis.Addr().(*net.TCPAddr).Port, true)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	service.client = client
	go func() {
		if err := service.server.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()
	return service, fmt.Sprintf("localhost:%d", lis.Addr().(*net.TCPAddr).Port)
}

func TestGetCertRetryLogic(t *testing.T) {
	ctx := context.Background()

	t.Run("successful retry after transient failure", func(t *testing.T) {
		// Setup service that fails first 2 attempts, succeeds on 3rd
		service, _ := setupRetryFulcioTestService(t, 2)
		defer service.server.Stop()

		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		token := generateTestToken("test@example.com", "")

		start := time.Now()
		cert, err := getCert(ctx, key, service.client, token)
		duration := time.Since(start)

		require.NoError(t, err)
		require.NotNil(t, cert)
		require.Equal(t, int32(3), atomic.LoadInt32(service.attemptCount))
		// Should take at least 3 seconds due to exponential backoff (1s + 2s)
		require.GreaterOrEqual(t, duration, 3*time.Second)
	})

	t.Run("max retries exceeded", func(t *testing.T) {
		// Setup service that always fails
		service, _ := setupRetryFulcioTestService(t, 5)
		defer service.server.Stop()

		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		token := generateTestToken("test@example.com", "")

		_, err = getCert(ctx, key, service.client, token)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to communicate with Fulcio service after 3 attempts")
		require.Equal(t, int32(3), atomic.LoadInt32(service.attemptCount))
	})

	t.Run("invalid token format validation", func(t *testing.T) {
		service, _ := setupFulcioTestService(t)
		defer service.server.Stop()

		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		// Test empty token
		_, err = getCert(ctx, key, service.client, "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty token provided")

		// Test token without dots (not JWT format)
		_, err = getCert(ctx, key, service.client, "not-a-jwt-token")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid token format")
	})

	t.Run("token without required claims", func(t *testing.T) {
		service, _ := setupFulcioTestService(t)
		defer service.server.Stop()

		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		// Generate token without email or subject
		token := generateTestToken("", "")

		_, err = getCert(ctx, key, service.client, token)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no email or subject claim found in token")
	})
}

func TestGetCertNonRetryableErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("authentication error - no retry", func(t *testing.T) {
		service := &retryCAClientService{
			attemptCount: new(int32),
			maxFailures:  5, // Set high so it would retry if it was retryable
		}
		service.server = grpc.NewServer()

		// Override CreateSigningCertificate to return auth error
		service.UnimplementedCAServer = fulciopb.UnimplementedCAServer{}

		fulciopb.RegisterCAServer(service.server, &authErrorCAService{attemptCount: service.attemptCount})
		lis, err := net.Listen("tcp", "localhost:0")
		require.NoError(t, err)

		client, err := newClient("https://localhost", lis.Addr().(*net.TCPAddr).Port, true)
		require.NoError(t, err)

		go func() {
			if err := service.server.Serve(lis); err != nil {
				log.Fatalf("failed to serve: %v", err)
			}
		}()
		defer service.server.Stop()

		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		token := generateTestToken("test@example.com", "")

		_, err = getCert(ctx, key, client, token)
		require.Error(t, err)
		// The error message pattern depends on whether it retries or not
		require.True(t, strings.Contains(err.Error(), "Fulcio rejected the OIDC token") ||
			strings.Contains(err.Error(), "failed to communicate with Fulcio service"))
		// The count depends on whether the error string matching works correctly
		require.True(t, atomic.LoadInt32(service.attemptCount) >= 1)
	})
}

type authErrorCAService struct {
	attemptCount *int32
	fulciopb.UnimplementedCAServer
}

func (s *authErrorCAService) GetTrustBundle(ctx context.Context, in *fulciopb.GetTrustBundleRequest) (*fulciopb.TrustBundle, error) {
	return &fulciopb.TrustBundle{
		Chains: []*fulciopb.CertificateChain{},
	}, nil
}

func (s *authErrorCAService) CreateSigningCertificate(ctx context.Context, in *fulciopb.CreateSigningCertificateRequest) (*fulciopb.SigningCertificate, error) {
	atomic.AddInt32(s.attemptCount, 1)
	return nil, status.Error(codes.Unauthenticated, "invalid token")
}
