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

//go:build timeout_test
// +build timeout_test

package fulcio

import (
	"context"
	"os"
	"testing"
	"time"
	
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"golang.org/x/oauth2"
)

// TestDemonstrateOAuthTimeout shows the 2-minute timeout in the OAuth interactive flow
func TestDemonstrateOAuthTimeout(t *testing.T) {
	// This test demonstrates that the interactive OAuth flow has a
	// hardcoded 2-minute timeout when waiting for the browser callback
	
	// Skip if not explicitly requested
	if os.Getenv("RUN_TIMEOUT_TEST") != "true" {
		t.Skip("Set RUN_TIMEOUT_TEST=true to run this 2-minute timeout test")
	}
	
	// Create the interactive token getter
	getter := &oauthflow.InteractiveIDTokenGetter{
		Input:  os.Stdin,
		Output: os.Stdout,
	}
	
	// Create OAuth config
	cfg := oauth2.Config{
		ClientID: "sigstore",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://oauth2.sigstore.dev/auth/auth",
			TokenURL: "https://oauth2.sigstore.dev/auth/token",
		},
		RedirectURL: "http://localhost:0/auth/callback",
		Scopes:      []string{"openid", "email"},
	}
	
	// Create a provider (mock)
	// In the real scenario, this would be an OIDC provider
	// but for our test, we just need to trigger the timeout
	
	t.Log("Starting OAuth interactive flow - this will timeout after 2 minutes")
	t.Log("The browser will open but the callback will never complete")
	
	start := time.Now()
	
	// This will timeout after exactly 120 seconds
	ctx := context.Background()
	_, err := getter.GetIDToken(nil, cfg)
	
	elapsed := time.Since(start)
	
	t.Logf("OAuth flow completed after: %v", elapsed)
	t.Logf("Error: %v", err)
	
	// Check if we hit the 2-minute timeout
	if elapsed >= 119*time.Second && elapsed <= 121*time.Second {
		t.Log("✅ CONFIRMED: OAuth interactive flow times out at exactly 120 seconds")
		t.Fatal("Hit the hardcoded 2-minute timeout")
	}
	
	if err != nil && err.Error() == "timeout" {
		t.Log("✅ Got timeout error as expected")
	}
}