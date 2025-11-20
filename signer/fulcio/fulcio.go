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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/registry"
	"github.com/in-toto/go-witness/signer"
	"github.com/mattn/go-isatty"
	fulciopb "github.com/sigstore/fulcio/pkg/generated/protobuf"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sigstore/sigstore/pkg/signature"
	sigo "github.com/sigstore/sigstore/pkg/signature/options"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"gopkg.in/go-jose/go-jose.v2/jwt"
)

func init() {
	signer.Register("fulcio", func() signer.SignerProvider { return New() },
		registry.StringConfigOption(
			"url",
			"Fulcio address to sign with",
			"",
			func(sp signer.SignerProvider, fulcioUrl string) (signer.SignerProvider, error) {
				fsp, ok := sp.(FulcioSignerProvider)
				if !ok {
					return sp, fmt.Errorf("provided signer provider is not a fulcio signer provider")
				}

				WithFulcioURL(fulcioUrl)(&fsp)
				return fsp, nil
			},
		),
		registry.StringConfigOption(
			"oidc-issuer",
			"OIDC issuer to use for authentication",
			"",
			func(sp signer.SignerProvider, oidcIssuer string) (signer.SignerProvider, error) {
				fsp, ok := sp.(FulcioSignerProvider)
				if !ok {
					return sp, fmt.Errorf("provided signer provider is not a fulcio signer provider")
				}

				WithOidcIssuer(oidcIssuer)(&fsp)
				return fsp, nil
			},
		),
		registry.StringConfigOption(
			"oidc-client-id",
			"OIDC client ID to use for authentication",
			"",
			func(sp signer.SignerProvider, oidcClientID string) (signer.SignerProvider, error) {
				fsp, ok := sp.(FulcioSignerProvider)
				if !ok {
					return sp, fmt.Errorf("provided signer provider is not a fulcio signer provider")
				}

				WithOidcClientID(oidcClientID)(&fsp)
				return fsp, nil
			},
		),
		registry.StringConfigOption(
			"token",
			"Raw token string to use for authentication to fulcio (cannot be used in conjunction with --fulcio-token-path)",
			"",
			func(sp signer.SignerProvider, token string) (signer.SignerProvider, error) {
				fsp, ok := sp.(FulcioSignerProvider)
				if !ok {
					return sp, fmt.Errorf("provided signer provider is not a fulcio signer provider")
				}

				WithToken(token)(&fsp)
				return fsp, nil
			},
		),
		registry.StringConfigOption(
			"oidc-redirect-url",
			"OIDC redirect URL (Optional). The default oidc-redirect-url is 'http://localhost:0/auth/callback'.",
			"",
			func(sp signer.SignerProvider, oidcRedirectUrl string) (signer.SignerProvider, error) {
				fsp, ok := sp.(FulcioSignerProvider)
				if !ok {
					return sp, fmt.Errorf("provided signer provider is not a fulcio signer provider")
				}

				WithOidcRedirectUrl(oidcRedirectUrl)(&fsp)
				return fsp, nil
			},
		),
		registry.StringConfigOption(
			"token-path",
			"Path to the file containing a raw token to use for authentication to fulcio (cannot be used in conjunction with --fulcio-token)",
			"",
			func(sp signer.SignerProvider, tokenPath string) (signer.SignerProvider, error) {
				fsp, ok := sp.(FulcioSignerProvider)
				if !ok {
					return sp, fmt.Errorf("provided signer provider is not a fulcio signer provider")
				}

				WithTokenPath(tokenPath)(&fsp)
				return fsp, nil
			},
		),
		registry.BoolConfigOption(
			"use-http",
			"HTTP/REST mode for Fulcio",
			false,
			func(sp signer.SignerProvider, useHttp bool) (signer.SignerProvider, error) {
				fsp, ok := sp.(FulcioSignerProvider)
				if !ok {
					return sp, fmt.Errorf("provided signer provider is not a fulcio signer provider")
				}
				WithUseHttp(useHttp)(&fsp)
				return fsp, nil
			},
		),
	)
}

type FulcioSignerProvider struct {
	FulcioURL       string
	OidcIssuer      string
	OidcClientID    string
	Token           string
	TokenPath       string
	OidcRedirectUrl string
	UseHTTP         bool
}

type Option func(*FulcioSignerProvider)

func WithFulcioURL(url string) Option {
	return func(fsp *FulcioSignerProvider) {
		fsp.FulcioURL = url
	}
}

func WithOidcIssuer(oidcIssuer string) Option {
	return func(fsp *FulcioSignerProvider) {
		fsp.OidcIssuer = oidcIssuer
	}
}

func WithOidcClientID(oidcClientID string) Option {
	return func(fsp *FulcioSignerProvider) {
		fsp.OidcClientID = oidcClientID
	}
}

func WithToken(tokenOption string) Option {
	return func(fsp *FulcioSignerProvider) {
		fsp.Token = tokenOption
	}
}

func WithOidcRedirectUrl(oidcRedirectUrl string) Option {
	return func(fsp *FulcioSignerProvider) {
		fsp.OidcRedirectUrl = oidcRedirectUrl
	}
}

func WithTokenPath(tokenPathOption string) Option {
	return func(fsp *FulcioSignerProvider) {
		fsp.TokenPath = tokenPathOption
	}
}

func WithUseHttp(useHttpOption bool) Option {
	return func(fsp *FulcioSignerProvider) {
		fsp.UseHTTP = useHttpOption
	}
}

func New(opts ...Option) FulcioSignerProvider {
	fsp := FulcioSignerProvider{}
	for _, opt := range opts {
		opt(&fsp)
	}

	return fsp
}

func (fsp FulcioSignerProvider) Signer(ctx context.Context) (cryptoutil.Signer, error) {
	// Parse the Fulcio URL to extract its components
	u, err := url.Parse(fsp.FulcioURL)
	if err != nil {
		return nil, err
	}
	// Get the scheme, default to HTTPS if not present
	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}

	// Get the port, default to 443
	port := 443
	if u.Port() != "" {
		p, err := strconv.Atoi(u.Port())
		if err != nil {
			return nil, fmt.Errorf("invalid port in Fulcio URL: %s", u.Port())
		}
		port = p
	}

	// Get the host, return an error if not present
	if u.Host == "" {
		return nil, errors.New("fulcio URL must include a host")
	}

	// Make insecure true only if the scheme is HTTP
	insecure := scheme == "http"

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	var raw string

	switch {
	case fsp.Token == "" && fsp.TokenPath == "" && os.Getenv("GITHUB_ACTIONS") == "true":
		tokenURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
		if tokenURL == "" {
			return nil, errors.New("ACTIONS_ID_TOKEN_REQUEST_URL is not set")
		}

		requestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
		if requestToken == "" {
			return nil, errors.New("ACTIONS_ID_TOKEN_REQUEST_TOKEN is not set")
		}

		log.Infof("Fetching GitHub Actions OIDC token from %s", tokenURL)
		raw, err = fetchToken(tokenURL, requestToken, "sigstore")
		if err != nil {
			return nil, fmt.Errorf("failed to fetch GitHub Actions OIDC token: %w", err)
		}
		log.Debugf("Successfully fetched GitHub Actions OIDC token")
	// we want to fail if both flags used (they're mutually exclusive)
	case fsp.TokenPath != "" && fsp.Token != "":
		return nil, errors.New("only one of --fulcio-token-path or --fulcio-raw-token can be used")
	case fsp.Token != "" && fsp.TokenPath == "":
		raw = fsp.Token
	case fsp.TokenPath != "" && fsp.Token == "":
		f, err := os.ReadFile(fsp.TokenPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read fulcio token from filepath %s: %w", fsp.TokenPath, err)
		}

		raw = string(f)
	case fsp.Token == "" && isatty.IsTerminal(os.Stdin.Fd()):
		tok, err := oauthflow.OIDConnect(fsp.OidcIssuer, fsp.OidcClientID, "", fsp.OidcRedirectUrl, oauthflow.DefaultIDTokenGetter)
		if err != nil {
			return nil, err
		}
		raw = tok.RawString
	default:
		return nil, errors.New("no token provided")
	}
	var certResp *fulciopb.SigningCertificate
	if fsp.UseHTTP {
		log.Info("Requesting signing certificate from Fulcio using HTTP")
		certResp, err = getCertHTTP(ctx, key, fsp.FulcioURL, raw)
		if err != nil {
			return nil, fmt.Errorf("failed to obtain certificate from Fulcio: %w", err)
		}
	} else {
		log.Infof("Requesting signing certificate from Fulcio at %s", scheme+"://"+u.Host)
		fClient, err := newClient(scheme+"://"+u.Host, port, insecure)
		if err != nil {
			return nil, err
		}
		certResp, err = getCert(ctx, key, fClient, raw)
		if err != nil {
			return nil, fmt.Errorf("failed to obtain certificate from Fulcio: %w", err)
		}
	}

	log.Debugf("Successfully received certificate response from Fulcio")
	var chain *fulciopb.CertificateChain

	switch cert := certResp.Certificate.(type) {
	case *fulciopb.SigningCertificate_SignedCertificateDetachedSct:
		chain = cert.SignedCertificateDetachedSct.GetChain()
	case *fulciopb.SigningCertificate_SignedCertificateEmbeddedSct:
		chain = cert.SignedCertificateEmbeddedSct.GetChain()
	}

	certs := chain.Certificates

	var intermediateCerts []*x509.Certificate
	var leafCert *x509.Certificate

	for i, certPEM := range certs {
		certDER, _ := pem.Decode([]byte(certPEM))
		if certDER == nil {
			return nil, fmt.Errorf("failed to decode PEM block for certificate %d/%d", i+1, len(certs))
		}

		cert, err := x509.ParseCertificate(certDER.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate %d/%d: %w", i+1, len(certs), err)
		}

		if cert.IsCA {
			intermediateCerts = append(intermediateCerts, cert)
		} else {
			leafCert = cert
		}
	}

	if leafCert == nil {
		return nil, errors.New("no leaf certificate found in Fulcio response")
	}

	ss := cryptoutil.NewECDSASigner(key, crypto.SHA256)
	if ss == nil {
		return nil, errors.New("failed to create RSA signer")
	}

	witnessSigner, err := cryptoutil.NewX509Signer(ss, leafCert, intermediateCerts, nil)
	if err != nil {
		return nil, err
	}

	return witnessSigner, nil
}

func getCert(ctx context.Context, key *ecdsa.PrivateKey, fc fulciopb.CAClient, token string) (*fulciopb.SigningCertificate, error) {
	// Validate token format before parsing
	if token == "" {
		return nil, errors.New("empty token provided to getCert")
	}

	if !strings.Contains(token, ".") {
		return nil, fmt.Errorf("invalid token format: token does not appear to be a JWT (missing dots)")
	}

	t, err := jwt.ParseSigned(token)
	if err != nil {
		// Check if the error is due to invalid JSON in the token
		if strings.Contains(err.Error(), "invalid character") {
			return nil, fmt.Errorf("failed to parse JWT token: invalid JSON in token payload - %w. This may indicate the OIDC token endpoint returned an error response instead of a token", err)
		}
		return nil, fmt.Errorf("failed to parse jwt token for fulcio: %w", err)
	}

	var claims struct {
		jwt.Claims
		Email   string `json:"email"`
		Subject string `json:"sub"`
	}

	if err := t.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract claims from JWT token: %w", err)
	}

	var tok *oauthflow.OIDCIDToken

	if claims.Email != "" {
		tok = &oauthflow.OIDCIDToken{
			RawString: token,
			Subject:   claims.Email,
		}
		log.Debugf("Using email claim from token: %s", claims.Email)
	} else if claims.Subject != "" {
		tok = &oauthflow.OIDCIDToken{
			RawString: token,
			Subject:   claims.Subject,
		}
		log.Debugf("Using subject claim from token: %s", claims.Subject)
	}

	if tok == nil || tok.Subject == "" {
		return nil, fmt.Errorf("no email or subject claim found in token. Claims: email=%q, subject=%q", claims.Email, claims.Subject)
	}

	msg := strings.NewReader(tok.Subject)

	signer, err := signature.LoadSigner(key, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	proof, err := signer.SignMessage(msg, sigo.WithCryptoSignerOpts(crypto.SHA256))
	if err != nil {
		return nil, err
	}

	pubBytesPEM, err := cryptoutils.MarshalPublicKeyToPEM(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	cscr := &fulciopb.CreateSigningCertificateRequest{
		Credentials: &fulciopb.Credentials{
			Credentials: &fulciopb.Credentials_OidcIdentityToken{
				OidcIdentityToken: token,
			},
		},
		Key: &fulciopb.CreateSigningCertificateRequest_PublicKeyRequest{
			PublicKeyRequest: &fulciopb.PublicKeyRequest{
				PublicKey: &fulciopb.PublicKey{
					Content: string(pubBytesPEM),
				},
				ProofOfPossession: proof,
			},
		},
	}

	// Retry logic with exponential backoff for Fulcio certificate creation
	const maxRetries = 3
	var lastErr error
	var sc *fulciopb.SigningCertificate

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			// Exponential backoff: 1s, 2s, 4s
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			log.Infof("Retrying Fulcio certificate request in %v (attempt %d/%d)", backoff, attempt+1, maxRetries)
			time.Sleep(backoff)
		}

		log.Infof("Requesting signing certificate from Fulcio for subject: %s (attempt %d/%d)", tok.Subject, attempt+1, maxRetries)
		sc, lastErr = fc.CreateSigningCertificate(ctx, cscr)
		if lastErr == nil {
			log.Debugf("Successfully obtained signing certificate from Fulcio")
			break
		}

		log.Errorf("Failed creating signing certificate from Fulcio (attempt %d/%d): %v", attempt+1, maxRetries, lastErr)

		// Use gRPC status codes to determine if error is retryable
		isRetryable := false
		if st, ok := status.FromError(lastErr); ok {
			switch st.Code() {
			case codes.Unauthenticated, codes.PermissionDenied, codes.InvalidArgument:
				log.Debugf("Non-retryable gRPC error: %v", st.Code())
				isRetryable = false
			case codes.Unavailable, codes.DeadlineExceeded:
				isRetryable = true
			}
		} else {
			// Fallback to string matching for non-gRPC errors
			if strings.Contains(lastErr.Error(), "invalid token") ||
				strings.Contains(lastErr.Error(), "unauthorized") ||
				strings.Contains(lastErr.Error(), "permission denied") ||
				strings.Contains(lastErr.Error(), "unauthenticated") {
				log.Debugf("Non-retryable error detected, aborting retry attempts")
				isRetryable = false
			} else {
				isRetryable = true
			}
		}

		if !isRetryable {
			break
		}
	}

	if lastErr != nil {
		// Add more context to common Fulcio errors
		if strings.Contains(lastErr.Error(), "rpc error") {
			return nil, fmt.Errorf("failed to communicate with Fulcio service after %d attempts: %w. This may indicate a network issue or Fulcio service unavailability", maxRetries, lastErr)
		}
		if strings.Contains(lastErr.Error(), "invalid token") || strings.Contains(lastErr.Error(), "unauthorized") {
			return nil, fmt.Errorf("fulcio rejected the OIDC token: %w. This may indicate token expiration or invalid issuer configuration", lastErr)
		}
		return nil, fmt.Errorf("failed to create signing certificate from Fulcio after %d attempts: %w", maxRetries, lastErr)
	}

	return sc, nil
}

func getCertHTTP(ctx context.Context, key *ecdsa.PrivateKey, fulcioURL string, token string) (*fulciopb.SigningCertificate, error) {
	t, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT token: %w", err)
	}
	var claims struct {
		jwt.Claims
		Email   string `json:"email"`
		Subject string `json:"sub"`
	}
	if err := t.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract claims from JWT token: %w", err)
	}
	subject := claims.Email
	if subject == "" {
		subject = claims.Subject
	}
	if subject == "" {
		return nil, errors.New("no email or subject claim found in token")
	}

	log.Debugf("Signing subject: %s", subject)

	msg := strings.NewReader(subject)
	signer, err := signature.LoadSigner(key, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	proof, err := signer.SignMessage(msg, sigo.WithCryptoSignerOpts(crypto.SHA256))
	if err != nil {
		return nil, err
	}

	pubBytesPEM, err := cryptoutils.MarshalPublicKeyToPEM(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	payload := map[string]interface{}{
		"credentials": map[string]string{
			"oidcIdentityToken": token,
		},
		"publicKeyRequest": map[string]interface{}{
			"publicKey": map[string]string{
				"content": string(pubBytesPEM),
			},
			"proofOfPossession": proof,
		},
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", fulcioURL+"/api/v2/signingCert", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP request failed with status: %s, body: %s", resp.Status, string(body))
	}

	var certResp fulciopb.SigningCertificate
	if err := protojson.Unmarshal(body, &certResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &certResp, nil
}

/*

$ ./bin/witness run -s test -o test.json --signer-fulcio-url https://fulcio.sigstore.dev --signer-fulcio-oidc-client-id sigstore --signer-fulcio-oidc-issuer https://oauth2.sigstore.dev/auth --timestamp-servers https://freetsa.org/tsr --signer-fulcio-use-http true -- echo "hello" > test.txt
Your browser will now be opened to:
https://oauth2.sigstore.dev/auth/auth?access_type=online&client_id=sigstore&code_challenge=YSfawYoFAe3FCY7CMsrmcJ9VZGNSfe-1lL80v29Vqvc&code_challenge_method=S256&nonce=35jziKyZSU2aeBDWGmROQvJlJ4m&redirect_uri=http%3A%2F%2Flocalhost%3A55796%2Fauth%2Fcallback&response_type=code&scope=openid+email&state=35jziJsyTFMHIRSxMM1L4aYSIPj
INFO    Requesting signing certificate from Fulcio using HTTP
INFO    Signing subject: rahulvs2809@gmail.com
INFO    Proof of possession: 30460221009a03b30d01fc98a426ba90778aa61610466904bfdf29ddd1d005ce51af2b164d022100aa12cc2953186a8eb4e87be236b023a68bceef9b1cbc65c14bd08db9c056774c
INFO    Sending payload: {"credentials":{"oidcIdentityToken":"eyJhbGciOiJSUzI1NiIsImtpZCI6ImVkY2YzYTc4OWRlN2Q5NDE2YjA0NTUxZDlkM2ZiODQyZDIxZjI0ZjkifQ.eyJpc3MiOiJodHRwczovL29hdXRoMi5zaWdzdG9yZS5kZXYvYXV0aCIsInN1YiI6IkNna3hNVGt3TnpBd05UTVNKbWgwZEhCek9pVXlSaVV5Um1kcGRHaDFZaTVqYjIwbE1rWnNiMmRwYmlVeVJtOWhkWFJvIiwiYXVkIjoic2lnc3RvcmUiLCJleHAiOjE3NjM2Mzg0NTgsImlhdCI6MTc2MzYzODM5OCwibm9uY2UiOiIzNWp6aUt5WlNVMmFlQkRXR21ST1F2SmxKNG0iLCJhdF9oYXNoIjoiRXIwNjE2MlJDMXp5ZUk5bUF5M2xtUSIsImNfaGFzaCI6ImJQQ1p5SGl4b25GalJVWGktVXJibXciLCJlbWFpbCI6InJhaHVsdnMyODA5QGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJmZWRlcmF0ZWRfY2xhaW1zIjp7ImNvbm5lY3Rvcl9pZCI6Imh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aCIsInVzZXJfaWQiOiIxMTkwNzAwNTMifX0.yPTpt6bPI1VxK97-OQ9qJdOI9LbJ4hL4KdHsp-RHxs6BMTZlD9kCJonpoqBnaH_hi2grvgsI6WZ7akP16xo1iokzMzq0zdm8seabHc01uymD-ijqp7YKmFEim6g8WknaEeO5oc4Q_TG07vkJsN_sKcXliHY5cACAIyOlLPpoCMfiyfSku3HJcmkAvI1CSsjyRTYGQqhZSfeYoU_V0EUnLik6jTUoUMCX2g5ESUswrZkXvg-J6V2As7bSL_ii7Z0q9tfpp1nw9Q2uSsy0FvYfoDyLEpLCpjgosJGw_1vfNhXp5CMpLbQN7rpOzNmw8uh_GPjvFupL9k5Tw9ls3n166g"},"publicKeyRequest":{"proofOfPossession":"MEYCIQCaA7MNAfyYpCa6kHeKphYQRmkEv98p3dHQBc5RrysWTQIhAKoSzClTGGqOtOh74jawI6aLzu+bHLxlwUvQjbnAVndM","publicKey":{"content":"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEl3IWUhA6LA60J+OXUuRRKtC7E3EW\ninD6SkFwG9IEszFoGwpQjM3HRdn7b+51VprE0yUpnSpvdA5iiHjG8wjVFA==\n-----END PUBLIC KEY-----\n"}}}
INFO    Request URL: https://fulcio.sigstore.dev/api/v2/signingCert
INFO    Request Headers: map[Accept:[application/json] Content-Type:[application/json]]
INFO    Response Status: 200 OK
INFO    Response Body: {"signedCertificateEmbeddedSct":{"chain":{"certificates":["-----BEGIN CERTIFICATE-----\nMIIC0zCCAlqgAwIBAgIUdSswjt7nvILCqjzq0coukNxqmbcwCgYIKoZIzj0EAwMw\nNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl\ncm1lZGlhdGUwHhcNMjUxMTIwMTEzMzE5WhcNMjUxMTIwMTE0MzE5WjAAMFkwEwYH\nKoZIzj0CAQYIKoZIzj0DAQcDQgAEl3IWUhA6LA60J+OXUuRRKtC7E3EWinD6SkFw\nG9IEszFoGwpQjM3HRdn7b+51VprE0yUpnSpvdA5iiHjG8wjVFKOCAXkwggF1MA4G\nA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQU2JFq\n8qMDY7WaRDNY6n4F+ckYMiIwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y\nZD8wIwYDVR0RAQH/BBkwF4EVcmFodWx2czI4MDlAZ21haWwuY29tMCwGCisGAQQB\ng78wAQEEHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDAuBgorBgEEAYO/\nMAEIBCAMHmh0dHBzOi8vZ2l0aHViLmNvbS9sb2dpbi9vYXV0aDCBigYKKwYBBAHW\neQIEAgR8BHoAeAB2AN09MGrGxxEyYxkeHJlnNwKiSl643jyt/4eKcoAvKe6OAAAB\nmqEKUQMAAAQDAEcwRQIgAUBVcVJdgBI9TMqggqoTSIpxhv2d6i7jgQl3eYNxG3sC\nIQD4attczUTumf4VbIhpfZHEnqkS/2NN7cIwlRnL6Kad8zAKBggqhkjOPQQDAwNn\nADBkAjBbwat7Tq0akQ+7SGv8Q/0mHaf6DvyqFp4X/l8mY92Z4yV1S/AMLNdQmSXW\nzYlSmRMCMAaYnzdI/IcSxP5OLsZcA+uwbGb0MO+FRVUhu/isOlW5Wtc8Q8uZOulU\nO5gvzLWHKQ==\n-----END CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\nMIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMw\nKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y\nMjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3Jl\nLmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0C\nAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV7\n7LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS\n0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYB\nBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjp\nKFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZI\nzj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJR\nnZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsP\nmygUY7Ii2zbdCdliiow=\n-----END CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\nMIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMw\nKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y\nMTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3Jl\nLmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7\nXeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxex\nX69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92j\nYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRY\nwB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQ\nKsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCM\nWP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9\nTNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ\n-----END CERTIFICATE-----"]}}}
INFO    Starting prematerial attestors stage...
INFO    Starting git attestor...
INFO    Starting environment attestor...
INFO    Finished environment attestor... (0.000194291s)
INFO    Finished git attestor... (0.222717667s)
INFO    Completed prematerial attestors stage...
INFO    Starting material attestors stage...
INFO    Starting material attestor...
INFO    Finished material attestor... (4.659590916s)
INFO    Completed material attestors stage...
INFO    Starting execute attestors stage...
INFO    Starting command-run attestor...
INFO    Finished command-run attestor... (0.00674s)
INFO    Completed execute attestors stage...
INFO    Starting product attestors stage...
INFO    Starting product attestor...
INFO    Finished product attestor... (4.029983s)
INFO    Completed product attestors stage...
INFO    Starting postproduct attestors stage...
INFO    Completed postproduct attestors stage...
witness (fix/isSPDX) $

func getCertHTTP(ctx context.Context, key *ecdsa.PrivateKey, fulcioURL string, token string) (*fulciopb.SigningCertificate, error) {
	// Parse the OIDC token to extract the subject
	t, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT token: %w", err)
	}
	var claims struct {
		jwt.Claims
		Email   string `json:"email"`
		Subject string `json:"sub"`
	}
	if err := t.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract claims from JWT token: %w", err)
	}
	subject := claims.Email
	if subject == "" {
		subject = claims.Subject
	}
	if subject == "" {
		return nil, errors.New("no email or subject claim found in token")
	}
	// Log the subject for debugging
	log.Infof("Signing subject: %s", subject)
	// Generate the proof of possession
	msg := strings.NewReader(subject)
	signer, err := signature.LoadSigner(key, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	proof, err := signer.SignMessage(msg, sigo.WithCryptoSignerOpts(crypto.SHA256))
	if err != nil {
		return nil, err
	}
	// Log the proof for debugging
	log.Infof("Proof of possession: %x", proof)
	// Marshal the public key to PEM
	pubBytesPEM, err := cryptoutils.MarshalPublicKeyToPEM(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	// Construct the payload
	payload := map[string]interface{}{
		"credentials": map[string]string{
			"oidcIdentityToken": token,
		},
		"publicKeyRequest": map[string]interface{}{
			"publicKey": map[string]string{
				"content": string(pubBytesPEM),
			},
			"proofOfPossession": proof,
		},
	}
	// Marshal the payload to JSON
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	// Log the payload for debugging
	log.Infof("Sending payload: %s", string(jsonPayload))
	// Create the HTTP request
	req, err := http.NewRequest("POST", fulcioURL+"/api/v2/signingCert", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// Log the request for debugging
	log.Infof("Request URL: %s", fulcioURL+"/api/v2/signingCert")
	log.Infof("Request Headers: %+v", req.Header)
	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// Log the response for debugging
	log.Infof("Response Status: %s", resp.Status)
	body, _ := io.ReadAll(resp.Body)
	log.Infof("Response Body: %s", string(body))
	// Check the response status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP request failed with status: %s, body: %s", resp.Status, string(body))
	}
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	log.Infof("Response Body: %s", string(body))
	var certResp fulciopb.SigningCertificate
	if err := protojson.Unmarshal(body, &certResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return &certResp, nil
}
*/
// func getCertHTTP(ctx context.Context, key *ecdsa.PrivateKey, fulcioURL string, token string) (*fulciopb.SigningCertificate, error) {
// 	pubBytesPEM, err := cryptoutils.MarshalPublicKeyToPEM(&key.PublicKey)
// 	if err != nil {
// 		return nil, err
// 	}
// 	msg := strings.NewReader("subject")
// 	signer, err := signature.LoadSigner(key, crypto.SHA256)
// 	if err != nil {
// 		return nil, err
// 	}
// 	proof, err := signer.SignMessage(msg, sigo.WithCryptoSignerOpts(crypto.SHA256))
// 	if err != nil {
// 		return nil, err
// 	}
// 	payload := map[string]interface{}{
// 		"credentials": map[string]string{
// 			"oidcIdentityToken": token,
// 		},
// 		"publicKeyRequest": map[string]interface{}{
// 			"publicKey": map[string]string{
// 				"content": string(pubBytesPEM),
// 			},
// 			"proofOfPossession": proof,
// 		},
// 	}
// 	log.Infof("Sending payload: %+v", payload)

// 	jsonPayload, err := json.Marshal(payload)

// 	if err != nil {
// 		return nil, err
// 	}
// 	log.Infof("Sending payload: %s", string(jsonPayload))
// 	log.Info(fulcioURL + "/api/v2/signingCert")
// 	resp, err := http.Post(fulcioURL+"/api/v2/signingCert", "application/json", bytes.NewBuffer(jsonPayload))
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer resp.Body.Close()
// 	if resp.StatusCode != http.StatusOK {
// 		return nil, fmt.Errorf("HTTP request failed with status: %s", resp.Status)
// 	}
// 	var sc fulciopb.SigningCertificate
// 	if err := json.NewDecoder(resp.Body).Decode(&sc); err != nil {
// 		return nil, err
// 	}
// 	return &sc, nil
// }

func newClient(fulcioURL string, fulcioPort int, isInsecure bool) (fulciopb.CAClient, error) {
	if isInsecure {
		log.Infof("Fulcio client is running in insecure mode")
	}

	// Parse the Fulcio URL
	u, err := url.Parse(fulcioURL)
	if err != nil {
		return nil, err
	}

	// Verify that the URL is valid based on the isInsecure flag
	if (u.Scheme != "https" && !isInsecure) || u.Host == "" {
		return nil, fmt.Errorf("invalid Fulcio URL: %s", fulcioURL)
	}

	// Set up the TLS configuration
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if isInsecure {
		tlsConfig.InsecureSkipVerify = true
	}

	creds := credentials.NewTLS(tlsConfig)

	// Set up the gRPC dial options
	dialOpts := []grpc.DialOption{}
	if isInsecure {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(creds))
	}

	// `passthrough` is used due to the default DNS resolver not properly recognizing no_proxy
	conn, err := grpc.NewClient("passthrough:///"+net.JoinHostPort(u.Hostname(), strconv.Itoa(fulcioPort)), dialOpts...)
	if err != nil {
		return nil, err
	}

	// Create the Fulcio client
	return fulciopb.NewCAClient(conn), nil
}
