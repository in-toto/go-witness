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

# Clean up all test artifacts

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

echo "Cleaning up test artifacts..."

# Remove witness binary
if [ -f "./witness" ]; then
    rm -f ./witness
    echo "   ✓ Removed witness binary"
fi

# Remove witness clone directory (in case build failed)
if [ -d "./witness-repo" ]; then
    rm -rf ./witness-repo
    echo "   ✓ Removed witness-repo"
fi

# Remove temporary test directories
for dir in tmp-*; do
    if [ -d "$dir" ]; then
        rm -rf "$dir"
        echo "   ✓ Removed $dir"
    fi
done

echo ""
echo "Cleanup complete!"
