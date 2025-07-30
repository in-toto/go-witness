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

//go:build integration
// +build integration

package fulcio

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestTimeoutWithInvalidGitHubToken demonstrates the actual 2-minute timeout
// This test simulates what happens in CI when the OAuth flow is triggered
func TestTimeoutWithInvalidGitHubToken(t *testing.T) {
	if os.Getenv("CI") != "true" {
		t.Skip("Skipping integration test outside of CI")
	}

	// Save and clear environment to force non-terminal flow
	origStdin := os.Stdin
	defer func() { os.Stdin = origStdin }()
	
	// Close stdin to simulate non-interactive environment
	os.Stdin = nil

	// Don't set GitHub Actions env vars, forcing default behavior
	origGHA := os.Getenv("GITHUB_ACTIONS")
	os.Unsetenv("GITHUB_ACTIONS")
	defer func() {
		if origGHA != "" {
			os.Setenv("GITHUB_ACTIONS", origGHA)
		}
	}()

	fsp := New(
		WithFulcioURL("https://fulcio.sigstore.dev"),
		WithOidcIssuer("https://oauth2.sigstore.dev/auth"),
		WithOidcClientID("sigstore"),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()

	start := time.Now()
	_, err := fsp.Signer(ctx)
	elapsed := time.Since(start)

	t.Logf("Signer creation took: %v", elapsed)
	t.Logf("Error: %v", err)

	// The bug: this will timeout after exactly 120 seconds
	if elapsed >= 119*time.Second && elapsed <= 121*time.Second {
		t.Errorf("Hit the 2-minute OAuth timeout! Elapsed: %v", elapsed)
		t.Log("This demonstrates the bug where non-terminal environments hit the interactive OAuth timeout")
	}

	if err == nil {
		t.Error("Expected error but got nil")
	}
}