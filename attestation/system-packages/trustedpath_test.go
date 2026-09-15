// Copyright 2026 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package systempackages

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// trustedToolPath must resolve the package manager from the fixed trusted directories and never from
// the caller-supplied $PATH, so a binary planted on $PATH cannot be substituted for the real tool.
func TestTrustedToolPathIgnoresPATH(t *testing.T) {
	dir := t.TempDir()
	planted := filepath.Join(dir, "dpkg-query")
	require.NoError(t, os.WriteFile(planted, []byte("dummy"), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	resolved := trustedToolPath("dpkg-query")
	require.NotEqual(t, planted, resolved, "trustedToolPath resolved the binary from $PATH")
	require.False(t, strings.HasPrefix(resolved, dir), "trustedToolPath returned a path inside the $PATH directory")
}

// A name that is not a plain base file name must resolve to the fail-closed sentinel rather than
// escaping the trusted directories.
func TestTrustedToolPathRejectsInvalidNames(t *testing.T) {
	sentinel := filepath.Join(os.DevNull, "invalid-tool-name")
	for _, name := range []string{"", ".", "..", "a/b", "/etc/evil"} {
		require.Equal(t, sentinel, trustedToolPath(name), "expected sentinel for name %q", name)
	}
}

// The returned path must always be an explicit path (containing a separator) so exec.Command never
// falls back to a $PATH lookup of a bare program name.
func TestTrustedToolPathNeverReturnsBareName(t *testing.T) {
	for _, name := range []string{"rpm", "dpkg-query"} {
		resolved := trustedToolPath(name)
		require.NotEqual(t, name, resolved)
		require.True(t, strings.ContainsRune(resolved, filepath.Separator),
			"resolved path %q for %q has no separator", resolved, name)
	}
}
