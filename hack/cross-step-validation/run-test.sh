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

# Main test runner for cross-step validation integration tests

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "Cross-Step Validation Integration Tests"
echo "=========================================="
echo ""

# Track results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to run a test
run_test() {
    local test_name="$1"
    local test_script="$2"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    echo ""
    echo "----------------------------------------"
    echo "Running: ${test_name}"
    echo "----------------------------------------"

    if bash "${test_script}"; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        echo -e "${GREEN}✓ ${test_name} PASSED${NC}"
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo -e "${RED}✗ ${test_name} FAILED${NC}"
    fi
}

# Build witness first
echo "Building witness binary..."
if bash ./build-witness.sh; then
    echo -e "${GREEN}✓ Witness built successfully${NC}"
else
    echo -e "${RED}✗ Failed to build witness${NC}"
    exit 1
fi

# Run tests
run_test "Successful Pipeline" "./test-success.sh"
run_test "Tampered Artifact Detection" "./test-tampered-artifact.sh"
run_test "Missing Dependency Detection" "./test-missing-dependency.sh"

# Clean up
echo ""
echo "----------------------------------------"
echo "Cleaning up..."
echo "----------------------------------------"
bash ./cleanup.sh

# Print summary
echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Total tests:  ${TOTAL_TESTS}"
echo -e "Passed:       ${GREEN}${PASSED_TESTS}${NC}"
echo -e "Failed:       ${RED}${FAILED_TESTS}${NC}"
echo ""

if [ ${FAILED_TESTS} -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi
