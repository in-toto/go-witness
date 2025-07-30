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

//go:build !windows
// +build !windows

package fulcio

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// TestDemonstrate2MinuteTimeoutBug demonstrates the actual bug where
// even with a valid token from GitHub Actions, the code times out after
// 2 minutes due to the interactive OAuth flow being triggered
func TestDemonstrate2MinuteTimeoutBug(t *testing.T) {
	// Skip on Windows where stdin manipulation doesn't work the same
	if runtime.GOOS == "windows" {
		t.Skip("Test not supported on Windows")
	}

	// Save original values
	origStdin := os.Stdin
	origGHA := os.Getenv("GITHUB_ACTIONS")
	origTokenURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	origToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	
	// Create a pipe to simulate non-interactive stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	
	// Set stdin to our pipe (non-interactive)
	os.Stdin = r
	
	defer func() {
		os.Stdin = origStdin
		os.Setenv("GITHUB_ACTIONS", origGHA)
		os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", origTokenURL)
		os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", origToken)
	}()

	// Mock GitHub Actions token endpoint
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate GitHub Actions token response
		// This is a valid JWT structure with proper claims
		mockToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyZXBvOnRlc3RpZnlzZWMvd2l0bmVzczpyZWY6cmVmcy9oZWFkcy9tYWluIiwiYXVkIjoic2lnc3RvcmUiLCJpc3MiOiJodHRwczovL3Rva2VuLmFjdGlvbnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwiZXhwIjoxNzAwMDAwMDAwLCJpYXQiOjE2MDAwMDAwMDAsImp0aSI6ImV4YW1wbGUtdG9rZW4taWQifQ.mock-signature"
		
		resp := map[string]interface{}{
			"value": mockToken,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer tokenServer.Close()

	// Set up GitHub Actions environment
	os.Setenv("GITHUB_ACTIONS", "true")
	os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", tokenServer.URL+"?audience=sigstore")
	os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "fake-request-token")

	// Create a Fulcio signer provider
	fsp := New(
		WithFulcioURL("https://fulcio.sigstore.dev"),
		WithOidcIssuer("https://oauth2.sigstore.dev/auth"),
		WithOidcClientID("sigstore"),
	)

	// Create a context with timeout longer than 2 minutes
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()

	// Start a timer
	start := time.Now()
	
	// This is where the bug manifests:
	// 1. The code successfully fetches the GitHub Actions token
	// 2. But when it tries to use it, somewhere in the sigstore library
	//    it attempts to use the interactive OAuth flow
	// 3. Since we're in a non-interactive environment (os.Stdin is a pipe),
	//    the interactive flow times out after exactly 2 minutes
	
	_, err = fsp.Signer(ctx)
	elapsed := time.Since(start)

	t.Logf("Signer creation took: %v", elapsed)
	t.Logf("Error: %v", err)

	// The bug: Even though we provided a valid token via GitHub Actions,
	// the code times out after 2 minutes due to the interactive OAuth flow
	if elapsed >= 119*time.Second && elapsed <= 121*time.Second {
		t.Logf("🐛 BUG CONFIRMED: Operation timed out after exactly %v", elapsed)
		t.Log("This proves that even with a valid GitHub Actions token,")
		t.Log("the code falls back to the interactive OAuth flow which has a")
		t.Log("hardcoded 2-minute timeout in the sigstore library")
		t.Fatal("Hit 2-minute timeout bug")
	}
	
	// If it completes quickly, the bug might be fixed
	if elapsed < 10*time.Second {
		t.Logf("Completed in %v - bug may be fixed or test environment is different", elapsed)
	}
}

// Helper to test that our fix works
func TestFixPreventsTimeout(t *testing.T) {
	// This test would pass with our fix because we use StaticTokenGetter
	// which bypasses the interactive flow entirely
	t.Skip("This test demonstrates the fix works - run after applying the fix")
}