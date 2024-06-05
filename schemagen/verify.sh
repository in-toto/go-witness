#!/bin/sh

# Copyright 2021 The Witness Contributors
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

set -e

# Verify that generated Markdown docs are up-to-date.
tmpdir=$(mktemp -d)
tmpdir2=$(mktemp -d)
cp ./schemagen/*.json "$tmpdir2/"
go run ./schemagen --dir "$tmpdir"
echo "###########################################"
echo "If diffs are found, run: make schema"
echo "###########################################"
diff -Nau "$tmpdir" "$tmpdir2"
rm -rf "$tmpdir" "$tmpdir2"
