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

//go:build demonstrate_timeout
// +build demonstrate_timeout

package fulcio

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
	"encoding/json"
	
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"golang.org/x/oauth2"
)

// TestDemonstrateInteractiveTimeout shows that the interactive OAuth flow
// times out after exactly 2 minutes when no callback is received
func TestDemonstrateInteractiveTimeout(t *testing.T) {
	// This test demonstrates the root cause of the timeout
	getter := &oauthflow.InteractiveIDTokenGetter{
		Input:  os.Stdin,
		Output: os.Stdout,
	}
	
	// Create a mock OAuth2 config that will never complete
	cfg := oauth2.Config{
		ClientID:     "sigstore",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://oauth2.sigstore.dev/auth",
			TokenURL: "https://oauth2.sigstore.dev/token",
		},
		RedirectURL: "http://localhost:0/auth/callback",
		Scopes:      []string{"openid", "email"},
	}
	
	// Simulate non-interactive environment
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	defer func() {
		os.Stdin = oldStdin
		r.Close()
		w.Close()
	}()
	
	// Start timer
	start := time.Now()
	
	// This will timeout after exactly 120 seconds
	ctx := context.Background()
	_, err := oauthflow.OIDConnect("https://oauth2.sigstore.dev/auth", "sigstore", "", "", getter)
	
	elapsed := time.Since(start)
	
	t.Logf("OAuth flow took: %v", elapsed)
	t.Logf("Error: %v", err)
	
	// The timeout happens at exactly 120 seconds
	if elapsed >= 119*time.Second && elapsed <= 121*time.Second {
		t.Log("✅ Confirmed: Interactive OAuth flow times out at 120 seconds")
		t.Fatal("Hit the 2-minute timeout in sigstore library")
	}
}

// TestActualBugScenario attempts to reproduce the actual bug scenario
// where GitHub Actions token is fetched but the flow still times out
func TestActualBugScenario(t *testing.T) {
	// Skip in CI to avoid actual timeout
	if os.Getenv("CI") == "true" && os.Getenv("FORCE_TIMEOUT_TEST") != "true" {
		t.Skip("Skipping timeout test in CI (set FORCE_TIMEOUT_TEST=true to run)")
	}
	
	// Save and restore environment
	origGHA := os.Getenv("GITHUB_ACTIONS")
	origURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	origToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	origStdin := os.Stdin
	
	defer func() {
		os.Setenv("GITHUB_ACTIONS", origGHA)
		os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", origURL)
		os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", origToken)
		os.Stdin = origStdin
	}()
	
	// Make stdin non-interactive
	r, w, _ := os.Pipe()
	os.Stdin = r
	defer func() {
		r.Close()
		w.Close()
	}()
	
	// Mock GitHub Actions token server
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a token that will pass initial validation but fail at Fulcio
		resp := map[string]string{
			"value": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyZXBvOnRlc3QvdGVzdDpyZWY6cmVmcy9oZWFkcy9tYWluIiwiYXVkIjoic2lnc3RvcmUiLCJpc3MiOiJodHRwczovL3Rva2VuLmFjdGlvbnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwiZXhwIjoxOTk5OTk5OTk5LCJpYXQiOjE2MDAwMDAwMDB9.test",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer tokenServer.Close()
	
	// Set up GitHub Actions environment
	os.Setenv("GITHUB_ACTIONS", "true")
	os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", tokenServer.URL)
	os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")
	
	// Now here's the key: We need to simulate a scenario where
	// the code has a token but still triggers the interactive flow.
	// This might happen if the token validation fails in a certain way.
	
	fsp := New(
		WithFulcioURL("https://fulcio.sigstore.dev"),
		WithOidcIssuer("https://oauth2.sigstore.dev/auth"),
		WithOidcClientID("sigstore"),
	)
	
	ctx, cancel := context.WithTimeout(context.Background(), 130*time.Second)
	defer cancel()
	
	start := time.Now()
	
	// This is where the bug would manifest:
	// 1. Token is fetched from GitHub Actions
	// 2. Something goes wrong (e.g., Fulcio rejects the token)
	// 3. Code falls back to interactive flow
	// 4. Interactive flow times out after 120 seconds
	
	_, err := fsp.Signer(ctx)
	elapsed := time.Since(start)
	
	t.Logf("Signer creation took: %v", elapsed)
	t.Logf("Error: %v", err)
	
	// Check if we hit the 2-minute timeout
	if elapsed >= 119*time.Second && elapsed <= 121*time.Second {
		t.Fatal("BUG CONFIRMED: Hit 2-minute timeout even with GitHub Actions token!")
	}
}

// TestStaticTokenGetterAvoidsBug shows how using StaticTokenGetter prevents the timeout
func TestStaticTokenGetterAvoidsBug(t *testing.T) {
	// This demonstrates that StaticTokenGetter doesn't have the timeout issue
	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiYXVkIjoic2lnc3RvcmUiLCJleHAiOjE5OTk5OTk5OTl9.test"
	
	getter := &oauthflow.StaticTokenGetter{
		RawToken: token,
	}
	
	// This should return immediately, not timeout
	start := time.Now()
	tok, err := getter.GetIDToken(nil, oauth2.Config{})
	elapsed := time.Since(start)
	
	t.Logf("StaticTokenGetter took: %v", elapsed)
	
	if elapsed > 1*time.Second {
		t.Errorf("StaticTokenGetter took too long: %v", elapsed)
	}
	
	if tok == nil && err == nil {
		t.Error("Expected either token or error from StaticTokenGetter")
	}
	
	t.Log("✅ StaticTokenGetter returns immediately without timeout")
}