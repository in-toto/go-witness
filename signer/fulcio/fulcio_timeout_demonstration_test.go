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

//go:build timeout_demonstration
// +build timeout_demonstration

package fulcio

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestDemonstrateTimeoutBug demonstrates the actual 2-minute timeout bug
// by simulating a non-interactive environment without valid tokens
func TestDemonstrateTimeoutBug(t *testing.T) {
	// Save original values
	origStdin := os.Stdin
	origGHA := os.Getenv("GITHUB_ACTIONS")
	origTokenURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	origToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	
	defer func() {
		os.Stdin = origStdin
		os.Setenv("GITHUB_ACTIONS", origGHA)
		os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", origTokenURL)
		os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", origToken)
	}()

	// Simulate non-interactive environment (like GitHub Actions)
	// by setting stdin to nil
	os.Stdin = nil
	
	// Clear GitHub Actions env vars to force fallback to interactive flow
	os.Unsetenv("GITHUB_ACTIONS")
	os.Unsetenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	os.Unsetenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")

	// Create a Fulcio signer provider
	fsp := New(
		WithFulcioURL("https://fulcio.sigstore.dev"),
		WithOidcIssuer("https://oauth2.sigstore.dev/auth"),
		WithOidcClientID("sigstore"),
	)

	// Measure how long it takes
	start := time.Now()
	
	// This should timeout after exactly 2 minutes due to the hardcoded
	// timeout in the interactive OAuth flow
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	
	_, err := fsp.Signer(ctx)
	elapsed := time.Since(start)

	t.Logf("Signer creation took: %v", elapsed)
	t.Logf("Error: %v", err)

	// Check if we hit the 2-minute timeout
	if elapsed >= 119*time.Second && elapsed <= 121*time.Second {
		t.Errorf("BUG CONFIRMED: Hit the 2-minute OAuth timeout! Elapsed: %v", elapsed)
		t.Log("This demonstrates that non-interactive environments timeout after exactly 120 seconds")
		t.Log("when the interactive OAuth flow is triggered")
	} else if elapsed < 10*time.Second {
		t.Log("Completed quickly - the bug may have been fixed or conditions weren't right")
	}
}