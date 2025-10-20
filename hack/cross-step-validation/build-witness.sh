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

# Build witness CLI binary using local go-witness implementation

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_WITNESS_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
WITNESS_CLONE_DIR="${SCRIPT_DIR}/witness-repo"

echo "Building witness CLI from source with local go-witness..."

# Clean up any previous clone
if [ -d "${WITNESS_CLONE_DIR}" ]; then
    echo "   Removing previous witness clone..."
    rm -rf "${WITNESS_CLONE_DIR}"
fi

# Clone witness CLI repository
echo "   Cloning witness CLI repository..."
git clone --depth 1 https://github.com/in-toto/witness.git "${WITNESS_CLONE_DIR}" 2>/dev/null

cd "${WITNESS_CLONE_DIR}"

# Add replace directive to use local go-witness
echo "   Adding replace directive for local go-witness..."
go mod edit -replace "github.com/in-toto/go-witness=${GO_WITNESS_ROOT}"

# Download dependencies
echo "   Downloading dependencies..."
go mod download

# Build the witness binary
echo "   Building witness binary..."
go build -o "${SCRIPT_DIR}/witness" .

echo "✓ Witness built successfully at ${SCRIPT_DIR}/witness"

# Clean up the clone
rm -rf "${WITNESS_CLONE_DIR}"

# Verify the binary works
"${SCRIPT_DIR}/witness" version || true
