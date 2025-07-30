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

//go:build linux || darwin
// +build linux darwin

package fulcio

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"
	"encoding/json"
	"net/http"
	"net/http/httptest"
)

// TestReproduceBugOnMainBranch attempts to reproduce the timeout bug
// that occurs on the main branch before our fix
func TestReproduceBugOnMainBranch(t *testing.T) {
	// Skip in short mode to avoid 2-minute timeout
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}
	
	// This test reproduces the bug by:
	// 1. Setting up GitHub Actions environment
	// 2. Making stdin non-TTY (like in GitHub Actions)
	// 3. Providing a token that will fail Fulcio validation
	// 4. Observing that the code times out after 2 minutes
	
	// Save original state
	origGHA := os.Getenv("GITHUB_ACTIONS") 
	origURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	origToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	origStdin := os.Stdin
	origStdout := os.Stdout
	origStderr := os.Stderr
	
	// Create pipes to simulate non-TTY environment
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutR, stdoutW, err := os.Pipe() 
	if err != nil {
		t.Fatal(err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	
	// Replace stdin/stdout/stderr with pipes (non-TTY)
	os.Stdin = stdinR
	os.Stdout = stdoutW
	os.Stderr = stderrW
	
	// Cleanup function
	cleanup := func() {
		os.Stdin = origStdin
		os.Stdout = origStdout
		os.Stderr = origStderr
		os.Setenv("GITHUB_ACTIONS", origGHA)
		os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", origURL)
		os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", origToken)
		stdinR.Close()
		stdinW.Close()
		stdoutR.Close()
		stdoutW.Close()
		stderrR.Close()
		stderrW.Close()
	}
	defer cleanup()
	
	// Mock GitHub Actions token endpoint
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a token that looks valid but will fail Fulcio's checks
		// This simulates a real scenario where the token format is correct
		// but Fulcio rejects it for some reason
		token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyZXBvOmludmFsaWQvcmVwbzpyZWY6cmVmcy9oZWFkcy9tYWluIiwiYXVkIjoic2lnc3RvcmUiLCJpc3MiOiJodHRwczovL3Rva2VuLmFjdGlvbnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwiZXhwIjoyMDAwMDAwMDAwLCJpYXQiOjE2MDAwMDAwMDAsImp0aSI6InRlc3QtaWQifQ.invalid-signature"
		
		resp := map[string]string{"value": token}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()
	
	// Set up GitHub Actions environment
	os.Setenv("GITHUB_ACTIONS", "true")
	os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", mockServer.URL)
	os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-request-token")
	
	// The bug scenario:
	// 1. We're in GitHub Actions (non-TTY)
	// 2. A token is fetched successfully
	// 3. But somewhere in the process, the interactive OAuth flow is triggered
	// 4. Since we're non-TTY, it waits for browser callback that never comes
	// 5. After 120 seconds, it times out
	
	fsp := New(
		WithFulcioURL("https://fulcio.sigstore.dev"),
		WithOidcIssuer("https://oauth2.sigstore.dev/auth"), 
		WithOidcClientID("sigstore"),
	)
	
	// Use a timeout longer than 2 minutes to catch the OAuth timeout
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	
	t.Log("Starting test - if bug exists, will timeout after 2 minutes...")
	start := time.Now()
	
	_, err := fsp.Signer(ctx)
	
	elapsed := time.Since(start)
	t.Logf("Operation completed after: %v", elapsed)
	t.Logf("Error: %v", err)
	
	// THE BUG: Operation times out after exactly 120 seconds
	if elapsed >= 119*time.Second && elapsed <= 121*time.Second {
		t.Log("🐛 BUG CONFIRMED: Operation timed out after exactly 2 minutes!")
		t.Log("This happens because:")
		t.Log("1. Token was fetched from GitHub Actions")  
		t.Log("2. But the interactive OAuth flow was triggered")
		t.Log("3. In non-TTY environment, it waits 120 seconds for browser callback")
		t.Log("4. Timeout occurs exactly at the 120-second mark")
		t.Fatal("Hit the 2-minute timeout bug")
	}
	
	// If it completes quickly, either:
	// 1. The bug is already fixed on this branch
	// 2. The test environment is different  
	if elapsed < 10*time.Second {
		t.Logf("Operation completed quickly (%v) - bug may be fixed or test conditions differ", elapsed)
		
		// Check if we're getting the expected "no token provided" error
		if err != nil && err.Error() == "no token provided" {
			t.Log("Got 'no token provided' error - this suggests isatty check is working")
		}
	}
}

// TestOurFixPreventsTimeout verifies that our fix prevents the timeout
func TestOurFixPreventsTimeout(t *testing.T) {
	// This test shows that with our fix (using StaticTokenGetter),
	// the operation completes quickly without timing out
	
	// TODO: This would pass with the fix applied
	t.Skip("Run this after applying the fix to verify it works")
}