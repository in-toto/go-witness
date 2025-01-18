// request_test.go

package vault

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRequestCertificate(t *testing.T) {
	tests := []struct {
		name            string
		baseURL         string
		pkiPath         string
		role            string
		namespace       string
		returnStatus    int
		returnBody      string
		simulateReadErr bool
		expectErr       bool
		wantErrContains string
	}{
		{
			name:         "success - minimal fields",
			baseURL:      "", // we'll override with test server
			pkiPath:      "pki",
			role:         "myrole",
			returnStatus: http.StatusOK,
			// Valid JSON body
			returnBody: `{
				"data": {
					"certificate": "cert-data",
					"issuing_ca": "issuing-ca",
					"ca_chain": ["intermediate-ca"],
					"private_key": "private-key-data",
					"private_key_type": "rsa",
					"serial_number": "1234"
				}
			}`,
			expectErr: false,
		},
		{
			name:            "http client read error",
			baseURL:         "",
			pkiPath:         "pki",
			role:            "myrole",
			returnStatus:    http.StatusOK,
			simulateReadErr: true, // forcibly close connection mid-response
			expectErr:       true,
			// Usually "unexpected EOF"
			wantErrContains: "unexpected EOF",
		},
		{
			name:            "non-200 response",
			baseURL:         "",
			pkiPath:         "pki",
			role:            "myrole",
			returnStatus:    http.StatusBadRequest,
			returnBody:      "bad request",
			expectErr:       true,
			wantErrContains: "failed to issue new certificate: bad request",
		},
		{
			name:         "malformed JSON on success code",
			baseURL:      "",
			pkiPath:      "pki",
			role:         "myrole",
			returnStatus: http.StatusOK,
			// Broken JSON => typically "unexpected end of JSON input"
			returnBody:      `{"data": "not an object"`, // missing closing brace
			expectErr:       true,
			wantErrContains: "unexpected end of JSON input",
		},
		{
			name:      "invalid base url for joinPath",
			baseURL:   "http://%", // invalid
			pkiPath:   "pki",
			role:      "myrole",
			expectErr: true,
			// Typically: parse "http://%": invalid URL escape "%"
			wantErrContains: `invalid URL escape`,
		},
		{
			name:         "namespace is set",
			baseURL:      "",
			pkiPath:      "pki2",
			role:         "testrole",
			namespace:    "my-namespace",
			returnStatus: http.StatusOK,
			returnBody: `{
				"data": {
					"certificate": "cert",
					"issuing_ca": "issuing-ca",
					"ca_chain": [],
					"private_key": "some-key",
					"private_key_type": "rsa",
					"serial_number": "abcd"
				}
			}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var server *httptest.Server

			// If baseURL is empty or we have a normal scenario, we create a test server
			if tc.baseURL == "" {
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// If we expect a namespace
					if tc.namespace != "" {
						require.Equal(t, tc.namespace, r.Header.Get("X-Vault-Namespace"))
					} else {
						require.Empty(t, r.Header.Get("X-Vault-Namespace"))
					}
					w.WriteHeader(tc.returnStatus)

					if tc.simulateReadErr {
						// forcibly close mid-response => read error
						hj, ok := w.(http.Hijacker)
						if !ok {
							// If hijack not supported (rare in tests), fallback
							_, _ = w.Write([]byte("partial data"))
							return
						}
						conn, _, _ := hj.Hijack()
						_, _ = conn.Write([]byte("partial data"))
						_ = conn.Close()
						return
					}
					// Normal scenario: write the body
					_, _ = w.Write([]byte(tc.returnBody))
				})

				server = httptest.NewServer(handler)
				defer server.Close()
				tc.baseURL = server.URL
			}

			vsp := &VaultSignerProvider{
				url:                  tc.baseURL,
				pkiSecretsEnginePath: tc.pkiPath,
				role:                 tc.role,
				namespace:            tc.namespace,
				token:                "dummy-token",
				commonName:           "testCN",
				// We rely on the real method
			}
			vsp.requestIssuer = vsp.requestCertificate

			resp, err := vsp.requestCertificate(context.Background())

			if tc.expectErr {
				require.Error(t, err)
				if tc.wantErrContains != "" {
					require.Contains(t, err.Error(), tc.wantErrContains)
				}
				return
			}

			// success path
			require.NoError(t, err, "expected no error but got one")
			require.NotEmpty(t, resp.Data.Certificate, "expected a certificate in response data")
		})
	}
}
