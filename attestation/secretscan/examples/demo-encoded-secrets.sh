#!/bin/bash
# Copyright 2025 The Witness Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Demo script for secretscan attestor's multi-layer encoding detection
# This script demonstrates how the secretscan attestor can detect secrets
# that have been encoded in various ways

set -e

# Create a temporary directory for our test files
DEMO_DIR=$(mktemp -d)
echo "Creating demo files in: $DEMO_DIR"

# Change to Witness repo root directory
cd "$(dirname "$0")/../../../"
REPO_ROOT=$(pwd)

# Set witness binary location - can be overridden with WITNESS_BIN env var
WITNESS_BIN=${WITNESS_BIN:-"./witness/witness"}

# Ensure witness binary exists
if [ ! -f "$WITNESS_BIN" ]; then
  echo "Witness binary not found at $WITNESS_BIN. Building..."
  make witness
  WITNESS_BIN="./witness/witness"
fi

# Create test key if it doesn't exist
if [ ! -f "testkey.pem" ]; then
  echo "Generating test key..."
  openssl genpkey -algorithm RSA -out testkey.pem
  openssl rsa -pubout -in testkey.pem -out testpub.pem
fi

# ==== Create test files with secrets in various encodings ====

# Plain text secret
echo "Creating plain text secret file..."
echo 'GITHUB_TOKEN=ghp_012345678901234567890123456789' > "$DEMO_DIR/plain-secret.txt"

# Base64-encoded secret
echo "Creating base64-encoded secret file..."
echo 'GITHUB_TOKEN=ghp_012345678901234567890123456789' | base64 > "$DEMO_DIR/base64-secret.txt"

# Double base64-encoded secret
echo "Creating double base64-encoded secret file..."
echo 'GITHUB_TOKEN=ghp_012345678901234567890123456789' | base64 | base64 > "$DEMO_DIR/double-base64-secret.txt"

# URL-encoded secret
echo "Creating URL-encoded secret file..."
URLENCODED=$(perl -MURI::Escape -e 'print uri_escape("GITHUB_TOKEN=ghp_012345678901234567890123456789");')
echo "$URLENCODED" > "$DEMO_DIR/url-encoded-secret.txt"

# Hex-encoded secret
echo "Creating hex-encoded secret file..."
xxd -p << EOF > "$DEMO_DIR/hex-encoded-secret.txt"
GITHUB_TOKEN=ghp_012345678901234567890123456789
EOF

# Mixed encoding: Base64 + URL
echo "Creating mixed encoding (base64 + URL) secret file..."
echo 'GITHUB_TOKEN=ghp_012345678901234567890123456789' | base64 | perl -MURI::Escape -e 'print uri_escape(<STDIN>);' > "$DEMO_DIR/mixed-encoding-secret.txt"

# ==== Run witness with secretscan attestor on each file ====

echo "==============================================================="
echo "Running secretscan attestor on plain text secret..."
echo "==============================================================="
"$WITNESS_BIN" run -a secretscan --log-level info -k testkey.pem -s test-step -o "$DEMO_DIR/plain-attestation.json" -- cat "$DEMO_DIR/plain-secret.txt"

echo "==============================================================="
echo "Running secretscan attestor on base64-encoded secret..."
echo "==============================================================="
"$WITNESS_BIN" run -a secretscan --log-level info -k testkey.pem -s test-step -o "$DEMO_DIR/base64-attestation.json" -- cat "$DEMO_DIR/base64-secret.txt"

echo "==============================================================="
echo "Running secretscan attestor on double base64-encoded secret..."
echo "==============================================================="
"$WITNESS_BIN" run -a secretscan --log-level info -k testkey.pem -s test-step -o "$DEMO_DIR/double-base64-attestation.json" -- cat "$DEMO_DIR/double-base64-secret.txt"

echo "==============================================================="
echo "Running secretscan attestor on URL-encoded secret..."
echo "==============================================================="
"$WITNESS_BIN" run -a secretscan --log-level info -k testkey.pem -s test-step -o "$DEMO_DIR/url-encoded-attestation.json" -- cat "$DEMO_DIR/url-encoded-secret.txt"

echo "==============================================================="
echo "Running secretscan attestor on hex-encoded secret..."
echo "==============================================================="
"$WITNESS_BIN" run -a secretscan --log-level info -k testkey.pem -s test-step -o "$DEMO_DIR/hex-encoded-attestation.json" -- cat "$DEMO_DIR/hex-encoded-secret.txt"

echo "==============================================================="
echo "Running secretscan attestor on mixed encoding secret..."
echo "==============================================================="
"$WITNESS_BIN" run -a secretscan --log-level info -k testkey.pem -s test-step -o "$DEMO_DIR/mixed-encoding-attestation.json" -- cat "$DEMO_DIR/mixed-encoding-secret.txt"

# ==== Display findings from attestations ====

echo "==============================================================="
echo "Extracting secretscan findings from attestations..."
echo "==============================================================="

# Function to extract findings from attestation JSON
extract_findings() {
  local file="$1"
  local name="$2"
  
  echo "=== $name Findings ==="
  jq -r '.payload' "$file" | base64 -d | jq '.predicate.attestations[] | select(.type=="https://witness.dev/attestations/secretscan/v0.1") | .attestation.findings'
  echo
}

extract_findings "$DEMO_DIR/plain-attestation.json" "Plain Text"
extract_findings "$DEMO_DIR/base64-attestation.json" "Base64 Encoded"
extract_findings "$DEMO_DIR/double-base64-attestation.json" "Double Base64 Encoded"
extract_findings "$DEMO_DIR/url-encoded-attestation.json" "URL Encoded"
extract_findings "$DEMO_DIR/hex-encoded-attestation.json" "Hex Encoded"
extract_findings "$DEMO_DIR/mixed-encoding-attestation.json" "Mixed Encoding"

echo "==============================================================="
echo "Demo complete. All files saved in: $DEMO_DIR"
echo "==============================================================="