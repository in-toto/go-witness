#!/bin/bash
# Script to demonstrate the 2-minute timeout bug in witness library

set -e

echo "=== Witness Library Timeout Bug Demonstration ==="
echo "This script shows how the Fulcio signer times out after 2 minutes"
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Create a test program that uses the library
cat > /tmp/timeout_demo.go << 'EOF'
package main

import (
    "context"
    "fmt"
    "os"
    "time"
    
    "github.com/in-toto/go-witness/signer/fulcio"
)

func main() {
    fmt.Println("Creating Fulcio signer in non-interactive mode...")
    fmt.Println("This will timeout after exactly 2 minutes if the bug exists")
    
    // Ensure we're in non-interactive mode
    if oldStdin := os.Stdin; oldStdin != nil {
        os.Stdin = nil
        defer func() { os.Stdin = oldStdin }()
    }
    
    fsp := fulcio.New(
        fulcio.WithFulcioURL("https://fulcio.sigstore.dev"),
        fulcio.WithOidcIssuer("https://oauth2.sigstore.dev/auth"),
        fulcio.WithOidcClientID("sigstore"),
    )
    
    ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
    defer cancel()
    
    start := time.Now()
    _, err := fsp.Signer(ctx)
    elapsed := time.Since(start)
    
    fmt.Printf("\nElapsed time: %v\n", elapsed)
    
    if elapsed >= 119*time.Second && elapsed <= 121*time.Second {
        fmt.Printf("\n%s✗ TIMEOUT BUG CONFIRMED!%s\n", "\033[0;31m", "\033[0m")
        fmt.Println("The OAuth flow timed out after exactly 2 minutes")
        os.Exit(1)
    }
    
    if err != nil {
        fmt.Printf("Error (expected): %v\n", err)
    }
}
EOF

echo "Running demonstration..."
echo

# Run the demo
cd /tmp
go mod init timeout-demo 2>/dev/null || true
go get github.com/in-toto/go-witness@main
go run timeout_demo.go