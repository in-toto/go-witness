// Copyright 2025 The Witness Contributors
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

package fulcio

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
	"encoding/json"
)

// TestReproduceTimeoutWithMocks attempts to reproduce the timeout bug
// by mocking the GitHub Actions token fetch
func TestReproduceTimeoutWithMocks(t *testing.T) {
	// Save original environment
	origGHA := os.Getenv("GITHUB_ACTIONS")
	origTokenURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	origToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	
	defer func() {
		os.Setenv("GITHUB_ACTIONS", origGHA)
		os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", origTokenURL)
		os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", origToken)
	}()

	// Create a mock server that simulates GitHub Actions token endpoint
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Log("Mock server received token request")
		
		// Return a valid-looking JWT token
		// This token has a proper structure but will fail Fulcio validation
		mockToken := map[string]string{
			"value": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyZXBvOnRlc3RvcmcvdGVzdHJlcG86cmVmOnJlZnMvaGVhZHMvbWFpbiIsImF1ZCI6InNpZ3N0b3JlIiwiaXNzIjoiaHR0cHM6Ly90b2tlbi5hY3Rpb25zLmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNjAwMDAwMDAwfQ.fake-signature",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockToken)
	}))
	defer mockServer.Close()

	// Set up GitHub Actions environment
	os.Setenv("GITHUB_ACTIONS", "true")
	os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", mockServer.URL)
	os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "mock-request-token")

	// Create Fulcio signer
	fsp := New(
		WithFulcioURL("https://fulcio.sigstore.dev"),
		WithOidcIssuer("https://oauth2.sigstore.dev/auth"),
		WithOidcClientID("sigstore"),
	)

	// Use a shorter timeout for the test
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	_, err := fsp.Signer(ctx)
	elapsed := time.Since(start)

	t.Logf("Operation took: %v", elapsed)
	t.Logf("Error: %v", err)

	// The current behavior should fail quickly with a Fulcio error
	// not timeout after 2 minutes
	if elapsed > 5*time.Second {
		t.Errorf("Operation took too long: %v", elapsed)
	}
}