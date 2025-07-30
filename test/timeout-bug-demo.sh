#!/bin/bash
# Script to demonstrate the 2-minute timeout bug in witness

set -e

echo "=== Witness Timeout Bug Demonstration ==="
echo "This script shows how witness times out after 2 minutes with long-running commands"
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Check if we're in GitHub Actions
if [ "$GITHUB_ACTIONS" = "true" ]; then
    echo "Running in GitHub Actions - OIDC token should be available"
    echo "ACTIONS_ID_TOKEN_REQUEST_URL is set: ${ACTIONS_ID_TOKEN_REQUEST_URL:+yes}"
    echo "ACTIONS_ID_TOKEN_REQUEST_TOKEN is set: ${ACTIONS_ID_TOKEN_REQUEST_TOKEN:+yes}"
else
    echo "Not running in GitHub Actions - setting up test environment"
fi

# Build witness if not already built
if [ ! -f "./bin/witness" ]; then
    echo "Building witness..."
    make build
fi

echo
echo "Testing with a command that takes 150 seconds (2.5 minutes)..."
echo "If the bug exists, this will timeout after exactly 120 seconds"
echo

# Record start time
START_TIME=$(date +%s)

# Run witness with a long command
set +e  # Don't exit on error
timeout 180 ./bin/witness run \
    -s timeout-test-$(date +%s) \
    --enable-archivist=false \
    --signer-fulcio-url=https://fulcio.sigstore.dev \
    --signer-fulcio-oidc-issuer=https://oauth2.sigstore.dev/auth \
    --signer-fulcio-oidc-client-id=sigstore \
    --attestor-product-exclude-glob="*" \
    -o /tmp/timeout-test-attestation.json \
    -- bash -c '
        echo "Command started at: $(date)"
        echo "This command will run for 150 seconds..."
        
        # Progress indicator
        for i in $(seq 1 15); do
            echo "Progress: $i/15 ($(($i * 10)) seconds elapsed)"
            sleep 10
        done
        
        echo "Command completed at: $(date)"
    '

EXIT_CODE=$?
set -e

# Record end time
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo
echo "========================================="
echo "Exit code: $EXIT_CODE"
echo "Elapsed time: $ELAPSED seconds"
echo "========================================="
echo

# Analyze the result
if [ $EXIT_CODE -eq 124 ]; then
    echo -e "${RED}✗ Command was killed by timeout${NC}"
    if [ $ELAPSED -ge 118 ] && [ $ELAPSED -le 125 ]; then
        echo -e "${RED}✗ TIMEOUT BUG CONFIRMED!${NC}"
        echo "The command timed out after ~2 minutes, confirming the OAuth timeout bug"
        exit 1
    fi
elif [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ Command completed successfully${NC}"
    if [ $ELAPSED -ge 140 ]; then
        echo -e "${GREEN}✓ No timeout bug - command ran for full duration${NC}"
    fi
    
    # Check if attestation was created
    if [ -f /tmp/timeout-test-attestation.json ]; then
        echo -e "${GREEN}✓ Attestation created successfully${NC}"
    fi
else
    echo -e "${RED}✗ Command failed with exit code $EXIT_CODE${NC}"
    echo "This might indicate a different issue"
fi

# Show any error logs
if [ $EXIT_CODE -ne 0 ] && [ -f /tmp/witness-error.log ]; then
    echo
    echo "Error details:"
    cat /tmp/witness-error.log
fi