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
)

// trustedToolDirs is the fixed set of system directories in which the package-manager binaries are
// expected to live. The list intentionally does not consult $PATH and intentionally omits
// /usr/local/bin: distro-packaged managers (rpm, dpkg-query) ship to /usr/bin or /usr/sbin, while
// /usr/local/bin is the conventional home for locally-installed tooling and is writable in some
// images and CI runners, which would weaken the trust boundary for no practical gain.
var trustedToolDirs = []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"}

// trustedToolPath returns an absolute path to the named package-manager binary, resolved only from a
// fixed set of trusted system directories rather than from the caller-supplied $PATH. Resolving a
// bare program name such as "rpm" / "dpkg-query" through $PATH would let whoever controls the
// environment substitute the binary. When the tool is not present in any trusted directory it
// returns a conventional absolute path so the command still bypasses $PATH lookup and simply fails
// to execute if the tool is genuinely absent.
//
// name must be a bare file name: callers pass constants, and rejecting anything other than a plain
// base name (absolute paths, "..", or embedded separators) keeps the trust boundary explicit so a
// future caller cannot escape trustedToolDirs via filepath.Join cleaning. A rejected name resolves
// to a path under /dev/null; since /dev/null is a character device, any path traversal through it
// fails with ENOTDIR, so exec fails closed instead of falling back to $PATH.
func trustedToolPath(name string) string {
	if name == "" || name == "." || name == ".." || name != filepath.Base(name) || strings.ContainsRune(name, filepath.Separator) {
		return filepath.Join(os.DevNull, "invalid-tool-name")
	}

	for _, dir := range trustedToolDirs {
		candidate := filepath.Join(dir, name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}

	return filepath.Join("/usr/bin", name)
}
