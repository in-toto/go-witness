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

//go:build integration && github_actions
// +build integration,github_actions

package fulcio_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestWitnessTimeoutBug tests the actual witness CLI to demonstrate the timeout
func TestWitnessTimeoutBug(t *testing.T) {
	// This test requires:
	// 1. Running in GitHub Actions (for OIDC token)
	// 2. witness binary to be built
	
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("This test requires GitHub Actions environment")
	}

	// Build witness if needed
	if _, err := os.Stat("../../bin/witness"); os.IsNotExist(err) {
		t.Log("Building witness...")
		cmd := exec.Command("make", "-C", "../..", "build")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("Failed to build witness: %v\n%s", err, out)
		}
	}

	t.Run("LongRunningCommand", func(t *testing.T) {
		// Create a context with timeout longer than 2 minutes
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		// Prepare witness command
		cmd := exec.CommandContext(ctx,
			"../../bin/witness", "run",
			"-s", "timeout-test",
			"--enable-archivist=false",
			"--signer-fulcio-url=https://fulcio.sigstore.dev",
			"--signer-fulcio-oidc-issuer=https://oauth2.sigstore.dev/auth",
			"--signer-fulcio-oidc-client-id=sigstore",
			"-o", "/tmp/test-attestation.json",
			"--",
			"bash", "-c", "echo 'Starting'; sleep 150; echo 'Done'",
		)

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		// Record timing
		start := time.Now()
		err := cmd.Run()
		elapsed := time.Since(start)

		t.Logf("Command elapsed time: %v", elapsed)
		t.Logf("Exit error: %v", err)
		t.Logf("Stdout: %s", stdout.String())
		t.Logf("Stderr: %s", stderr.String())

		// Check for timeout
		if elapsed >= 119*time.Second && elapsed <= 121*time.Second {
			t.Errorf("Command timed out after ~2 minutes (%v), indicating the OAuth timeout bug", elapsed)
			
			// Check for timeout-related errors in output
			if strings.Contains(stderr.String(), "timeout") {
				t.Log("Found 'timeout' in error output - bug confirmed")
			}
		}

		// The command should have succeeded if the bug is fixed
		if err == nil && elapsed > 140*time.Second {
			t.Log("✓ Command completed successfully without timeout")
		}
	})
}

// TestWitnessQuickCommand verifies that short commands work fine
func TestWitnessQuickCommand(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("This test requires GitHub Actions environment")
	}

	// This should always work, even with the bug
	cmd := exec.Command(
		"../../bin/witness", "run",
		"-s", "quick-test",
		"--enable-archivist=false",
		"--signer-fulcio-url=https://fulcio.sigstore.dev",
		"--signer-fulcio-oidc-issuer=https://oauth2.sigstore.dev/auth",
		"--signer-fulcio-oidc-client-id=sigstore",
		"--",
		"echo", "Quick test",
	)

	start := time.Now()
	out, err := cmd.CombinedOutput()
	elapsed := time.Since(start)

	t.Logf("Quick command took: %v", elapsed)
	t.Logf("Output: %s", out)

	if err != nil {
		t.Errorf("Quick command failed: %v", err)
	}

	if elapsed > 10*time.Second {
		t.Errorf("Quick command took too long: %v", elapsed)
	}
}