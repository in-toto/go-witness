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
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFetchToken(t *testing.T) {
	tokenURL := "https://example.com/token"
	bearer := "some-bearer-token"
	audience := "witness"

	// Test empty input.
	_, err := fetchToken("", bearer, audience)
	require.Error(t, err)

	_, err = fetchToken(tokenURL, "", audience)
	require.Error(t, err)

	_, err = fetchToken(tokenURL, bearer, "")
	require.Error(t, err)

	// Test invalid input.
	u, _ := url.Parse(tokenURL)
	q := u.Query()
	q.Set("audience", "other-audience")
	u.RawQuery = q.Encode()

	_, err = fetchToken(u.String(), bearer, audience)
	require.Error(t, err)

	// Test valid input.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "bearer "+bearer {
			http.Error(w, "Invalid bearer token", http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("audience") != audience {
			http.Error(w, "Invalid audience", http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, `{"count": 1, "value": "some-token"}`)
	}))
	defer server.Close()

	tokenURL = server.URL + "/token"

	token, err := fetchToken(tokenURL, bearer, audience)
	require.NoError(t, err)
	require.Equal(t, "some-token", token)
}

func TestFetchTokenRetryLogic(t *testing.T) {
	bearer := "some-bearer-token"
	audience := "witness"

	t.Run("successful retry after transient failure", func(t *testing.T) {
		var attemptCount int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count := atomic.AddInt32(&attemptCount, 1)
			if count <= 2 {
				// First two attempts fail with 500
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			// Third attempt succeeds
			fmt.Fprintf(w, `{"count": 1, "value": "retry-success-token"}`)
		}))
		defer server.Close()

		start := time.Now()
		token, err := fetchToken(server.URL+"/token", bearer, audience)
		duration := time.Since(start)

		require.NoError(t, err)
		require.Equal(t, "retry-success-token", token)
		require.Equal(t, int32(3), atomic.LoadInt32(&attemptCount))
		// Should take at least 3 seconds due to exponential backoff (1s + 2s)
		require.GreaterOrEqual(t, duration, 3*time.Second)
	})

	t.Run("max retries exceeded", func(t *testing.T) {
		var attemptCount int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&attemptCount, 1)
			http.Error(w, "Persistent failure", http.StatusInternalServerError)
		}))
		defer server.Close()

		_, err := fetchToken(server.URL+"/token", bearer, audience)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to fetch GitHub Actions token after 3 attempts")
		require.Equal(t, int32(3), atomic.LoadInt32(&attemptCount))
	})

	t.Run("HTML response handling", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<html><body>Error page</body></html>")
		}))
		defer server.Close()

		_, err := fetchToken(server.URL+"/token", bearer, audience)
		require.Error(t, err)
		require.Contains(t, err.Error(), "received HTML response instead of JSON")
	})

	t.Run("empty response handling", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Return empty body
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		_, err := fetchToken(server.URL+"/token", bearer, audience)
		require.Error(t, err)
		require.Contains(t, err.Error(), "received empty response")
	})

	t.Run("empty token value in response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"count": 1, "value": ""}`)
		}))
		defer server.Close()

		_, err := fetchToken(server.URL+"/token", bearer, audience)
		require.Error(t, err)
		require.Contains(t, err.Error(), "received empty token value")
	})

	t.Run("malformed JSON response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"count": 1, "value": "token"`) // missing closing brace
		}))
		defer server.Close()

		_, err := fetchToken(server.URL+"/token", bearer, audience)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse JSON response")
	})

}
