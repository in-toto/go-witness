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
	"os"
	"testing"
	"time"
)

// TestGitHubActionsTokenTimeout demonstrates that when a GitHub Actions token
// is available, the signer should use it directly instead of falling back to
// the interactive OAuth flow which has a 2-minute timeout.
func TestGitHubActionsTokenTimeout(t *testing.T) {
	// Skip if not in CI or if we don't have the required environment
	if os.Getenv("CI") != "true" {
		t.Skip("Skipping test outside of CI environment")
	}

	// Save original env vars
	origGHA := os.Getenv("GITHUB_ACTIONS")
	origTokenURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	origToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	defer func() {
		os.Setenv("GITHUB_ACTIONS", origGHA)
		os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", origTokenURL)
		os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", origToken)
	}()

	// Set up GitHub Actions environment
	os.Setenv("GITHUB_ACTIONS", "true")
	os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.com/token")
	os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "fake-token")

	// Create a Fulcio signer provider
	fsp := New(
		WithFulcioURL("https://fulcio.sigstore.dev"),
		WithOidcIssuer("https://oauth2.sigstore.dev/auth"),
		WithOidcClientID("sigstore"),
	)

	// Create a context with a timeout longer than 2 minutes to ensure
	// we can detect if the OAuth timeout (2 minutes) is hit
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// This should fail because fetchToken will fail with our fake URL,
	// but the important part is that it should fail immediately, not after
	// a 2-minute timeout from the interactive OAuth flow
	start := time.Now()
	_, err := fsp.Signer(ctx)
	elapsed := time.Since(start)

	// We expect an error because our fake token URL won't work
	if err == nil {
		t.Fatal("Expected error with fake token URL, got nil")
	}

	// The key assertion: if this takes close to 2 minutes, it means
	// we're hitting the interactive OAuth timeout instead of using
	// the token directly
	if elapsed > 30*time.Second {
		t.Errorf("Signer took %v, which suggests it's using the interactive OAuth flow (2-minute timeout) instead of the static token", elapsed)
	}
}

// TestStaticTokenUsage verifies that when a token is provided directly,
// it should be used without going through the interactive flow
func TestStaticTokenUsage(t *testing.T) {
	// Create a mock JWT token (this is just for testing, not a real token)
	mockToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ"

	// Test with direct token
	fsp := New(
		WithFulcioURL("https://fulcio.sigstore.dev"),
		WithOidcIssuer("https://oauth2.sigstore.dev/auth"),
		WithOidcClientID("sigstore"),
		WithToken(mockToken),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	_, err := fsp.Signer(ctx)
	elapsed := time.Since(start)

	// This will likely fail because our mock token isn't valid,
	// but it should fail quickly, not after a timeout
	if err == nil {
		t.Fatal("Expected error with mock token, got nil")
	}

	// Should fail almost immediately, not after 2 minutes
	if elapsed > 5*time.Second {
		t.Errorf("Signer with static token took %v, expected immediate response", elapsed)
	}
}