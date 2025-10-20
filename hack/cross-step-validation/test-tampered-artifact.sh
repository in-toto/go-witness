#!/usr/bin/env bash
# Copyright 2025.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Test tampered artifact detection using cross-step validation

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# Ensure witness is built
if [ ! -f "./witness" ]; then
    echo "Building witness..."
    ./build-witness.sh
fi

echo "=== Test: Tampered Artifact Detection ==="
echo ""

# Setup test directory
TEST_DIR="${SCRIPT_DIR}/tmp-tampered"
rm -rf "${TEST_DIR}"
mkdir -p "${TEST_DIR}"
cd "${TEST_DIR}"

echo "1. Generating keys..."
# Generate signing keys
openssl genpkey -algorithm ed25519 -out build-key.pem 2>/dev/null
openssl pkey -in build-key.pem -pubout -out build-key-pub.pem 2>/dev/null
openssl genpkey -algorithm ed25519 -out policy-key.pem 2>/dev/null
openssl pkey -in policy-key.pem -pubout -out policy-key-pub.pem 2>/dev/null
echo "   ✓ Keys generated"

# Create a simple Go program to build
echo "2. Creating test application..."
cat > main.go <<'EOF'
package main
import "fmt"
func main() {
    fmt.Println("Hello, Witness!")
}
EOF
echo "   ✓ Test app created"

# Step 1: Build
echo "3. Running build step..."
"${SCRIPT_DIR}/witness" run \
    --step build \
    --attestations material,product \
    --signer-file-key-path build-key.pem \
    --outfile build.json \
    -- go build -o app main.go
echo "   ✓ Build attestation created"

# TAMPER WITH THE ARTIFACT
echo "4. Tampering with artifact..."
echo "TAMPERED" >> app
echo "   ✓ Artifact modified (tampered)"

# Step 2: Test (uses the TAMPERED app binary)
echo "5. Running test step on tampered artifact..."
# This will succeed in creating attestation, but hash will be different
"${SCRIPT_DIR}/witness" run \
    --step test \
    --attestations material,product \
    --signer-file-key-path build-key.pem \
    --outfile test.json \
    -- echo "Running tests on tampered binary"
echo "   ✓ Test attestation created (with tampered artifact hash)"

# Step 3: Package
echo "6. Running package step..."
"${SCRIPT_DIR}/witness" run \
    --step package \
    --attestations material,product \
    --signer-file-key-path build-key.pem \
    --outfile package.json \
    -- tar -czf app.tar.gz app
echo "   ✓ Package attestation created"

# Get key ID from attestation
echo "7. Creating policy with cross-step validation..."
KEY_ID=$(cat build.json | grep -o '"keyid":"[^"]*"' | head -1 | cut -d'"' -f4)
PUB_KEY_B64=$(base64 < build-key-pub.pem | tr -d '\n')

# Create Rego policy for test step - validates against build output
TEST_REGO=$(cat <<'REGO' | base64 | tr -d '\n'
package material

deny[msg] {
    # Get test step's app material hash
    test_material := input.attestation["app"]["sha256"]

    # Get build step's app product hash
    build_product := input.steps.build.products["app"].digest["sha256"]

    # They must match
    test_material != build_product
    msg := "artifact chain validation failed: test input doesn't match build output - tampering detected"
}
REGO
)

# Create policy
cat > policy.json <<EOF
{
  "expires": "2026-12-31T23:59:59Z",
  "steps": {
    "build": {
      "name": "build",
      "functionaries": [
        {
          "type": "publickey",
          "publickeyid": "${KEY_ID}"
        }
      ],
      "attestations": [
        {"type": "https://witness.dev/attestations/material/v0.1"},
        {"type": "https://witness.dev/attestations/product/v0.1"}
      ]
    },
    "test": {
      "name": "test",
      "attestationsFrom": ["build"],
      "functionaries": [
        {
          "type": "publickey",
          "publickeyid": "${KEY_ID}"
        }
      ],
      "attestations": [
        {
          "type": "https://witness.dev/attestations/material/v0.1",
          "regopolicies": [
            {
              "name": "test-artifact-chain",
              "module": "${TEST_REGO}"
            }
          ]
        },
        {"type": "https://witness.dev/attestations/product/v0.1"}
      ]
    },
    "package": {
      "name": "package",
      "functionaries": [
        {
          "type": "publickey",
          "publickeyid": "${KEY_ID}"
        }
      ],
      "attestations": [
        {"type": "https://witness.dev/attestations/material/v0.1"},
        {"type": "https://witness.dev/attestations/product/v0.1"}
      ]
    }
  },
  "publickeys": {
    "${KEY_ID}": {
      "keyid": "${KEY_ID}",
      "key": "${PUB_KEY_B64}"
    }
  }
}
EOF

# Sign policy
"${SCRIPT_DIR}/witness" sign \
    --infile policy.json \
    --outfile policy-signed.json \
    --signer-file-key-path policy-key.pem
echo "   ✓ Policy created and signed"

# Verify - should FAIL due to tampering
echo "8. Verifying pipeline (should detect tampering)..."
if "${SCRIPT_DIR}/witness" verify \
    --policy policy-signed.json \
    --publickey policy-key-pub.pem \
    -a build.json \
    -a test.json \
    -a package.json \
    -s app 2>&1 | tee verify-output.txt; then
    echo "   ✗ Verification PASSED (should have failed!)"
    echo ""
    echo "FAILURE: Tampering was NOT detected!"
    cat verify-output.txt
    exit 1
else
    echo "   ✓ Verification FAILED (as expected)"

    # Check that error message mentions artifact chain validation
    if grep -q "artifact chain validation failed" verify-output.txt || \
       grep -q "tampering detected" verify-output.txt || \
       grep -q "test input doesn't match build output" verify-output.txt; then
        echo ""
        echo "SUCCESS: Tampered artifact detected by cross-step validation!"
        echo ""
        echo "Error message:"
        grep -i "artifact\|tamper" verify-output.txt || true
        cd "${SCRIPT_DIR}"
        rm -rf "${TEST_DIR}"
        exit 0
    else
        echo ""
        echo "FAILURE: Verification failed but not with expected error message"
        echo "Expected error about artifact chain validation or tampering"
        echo ""
        echo "Actual output:"
        cat verify-output.txt
        exit 1
    fi
fi
