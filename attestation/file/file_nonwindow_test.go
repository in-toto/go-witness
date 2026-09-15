// Copyright 2025 The Witness Contributors
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

//go:build !windows

package file

import (
	"crypto"
	"os"
	"path/filepath"
	"testing"

	"github.com/gobwas/glob"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/stretchr/testify/require"
)

func TestDirHash(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "testfile")
	require.NoError(t, os.WriteFile(testFile, []byte("some dummy data"), os.ModePerm))
	testDir := filepath.Join(dir, "testdir")
	require.NoError(t, os.Mkdir(testDir, os.ModePerm))
	testFile2 := filepath.Join(testDir, "testfile2")
	require.NoError(t, os.WriteFile(testFile2, []byte("more dummy data"), os.ModePerm))

	dirHashGlobs := make([]glob.Glob, 0)

	dirHash := "testdir"
	dirHashGlobItem, _ := glob.Compile(dirHash)
	dirHashGlobs = append(dirHashGlobs, dirHashGlobItem)

	artifacts, err := RecordArtifacts(dir, map[string]cryptoutil.DigestSet{}, []cryptoutil.DigestValue{{Hash: crypto.SHA256}}, map[string]struct{}{}, false, map[string]bool{}, dirHashGlobs)
	require.NoError(t, err)

	// Below command is example usage on the above created scenario for testdir.
	// find . -type f | cut -c3- | LC_ALL=C sort | xargs -r sha256sum | sha256sum
	dirHashSha256 := "ba9842eac063209c5f67c5a202b2b3a710f8f845f1d064f54af56763645b895b"

	require.Len(t, artifacts, 2)

	dirDigestSet := artifacts["testdir/"]
	dirDigestSetMap, err := dirDigestSet.ToNameMap()
	require.NoError(t, err)

	require.Equal(t, dirDigestSetMap["dirHash"], dirHashSha256)
}

func TestDirHashWithSymlink(t *testing.T) {
	dir := t.TempDir()

	// Create a directory structure with symlinks
	testDir := filepath.Join(dir, "testdir")
	require.NoError(t, os.Mkdir(testDir, os.ModePerm))
	testDir2 := filepath.Join(testDir, "testdir2")
	require.NoError(t, os.Mkdir(testDir2, os.ModePerm))
	symlinkDir := filepath.Join(testDir, "symlinkdir")
	require.NoError(t, os.Symlink(testDir2, symlinkDir))

	dirHashGlobs := make([]glob.Glob, 0)
	dirHash := "testdir"
	dirHashGlobItem, _ := glob.Compile(dirHash)
	dirHashGlobs = append(dirHashGlobs, dirHashGlobItem)

	artifacts, err := RecordArtifacts(dir, map[string]cryptoutil.DigestSet{}, []cryptoutil.DigestValue{{Hash: crypto.SHA256}}, map[string]struct{}{}, false, map[string]bool{}, dirHashGlobs)
	require.NoError(t, err)

	// Below command is example usage on the above created scenario for testdir.
	// find . -type f | cut -c3- | LC_ALL=C sort | xargs -r sha256sum | sha256sum
	dirHashSha256 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	require.Len(t, artifacts, 1) // testdir/

	// The original directory path should be used in the artifacts map
	dirDigestSet := artifacts["testdir/"]
	dirDigestSetMap, err := dirDigestSet.ToNameMap()
	require.NoError(t, err)

	require.Equal(t, dirDigestSetMap["dirHash"], dirHashSha256)
}

// RecordArtifacts must not follow a symlink whose target resolves outside the attested tree; an
// out-of-tree file reachable only through such a symlink must never be recorded.
func TestRecordArtifactsSkipsSymlinkOutsideBase(t *testing.T) {
	// A directory outside the attested tree holding a file that must never be reached.
	outside := t.TempDir()
	outsidePath := filepath.Join(outside, "secret.txt")
	require.NoError(t, os.WriteFile(outsidePath, []byte("out-of-tree"), 0o600))

	// The attested tree: one in-tree file plus a symlink that escapes to the outside file.
	base := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(base, "realfile.txt"), []byte("in-tree"), 0o644))
	require.NoError(t, os.Symlink(outsidePath, filepath.Join(base, "escape.link")))

	artifacts, err := RecordArtifacts(
		base,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		[]glob.Glob{},
	)
	require.NoError(t, err)

	// Nothing recorded should resolve to the out-of-tree file.
	resolvedOutside, err := filepath.EvalSymlinks(outsidePath)
	require.NoError(t, err)
	for recorded := range artifacts {
		abs, err := filepath.Abs(filepath.Join(base, recorded))
		require.NoError(t, err)
		resolved, err := filepath.EvalSymlinks(abs)
		if err != nil {
			continue
		}
		require.NotEqual(t, resolvedOutside, resolved,
			"recorded artifact %q resolves outside the attested tree", recorded)
	}
}

// Directory hashing follows symlinks while reading file contents and cannot selectively skip an
// escaping symlink the way the per-file walk does, so RecordArtifacts must fail closed when a hashed
// directory contains a symlink resolving outside the attested root.
func TestRecordArtifactsDirHashRefusesEscapingSymlink(t *testing.T) {
	outside := t.TempDir()
	outsidePath := filepath.Join(outside, "secret.txt")
	require.NoError(t, os.WriteFile(outsidePath, []byte("out-of-tree"), 0o600))

	base := t.TempDir()
	hashedDir := filepath.Join(base, "hasheddir")
	require.NoError(t, os.Mkdir(hashedDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(hashedDir, "real.txt"), []byte("in-tree"), 0o644))
	require.NoError(t, os.Symlink(outsidePath, filepath.Join(hashedDir, "escape.link")))

	dirHash := []glob.Glob{glob.MustCompile("hasheddir")}

	_, err := RecordArtifacts(
		base,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		dirHash,
	)
	require.Error(t, err, "dir-hash mode must refuse a hashed directory containing an escaping symlink")
	require.Contains(t, err.Error(), "refusing to hash directory")
}

// The escaping-symlink guard must be specific to symlinks that leave the attested root: a symlink
// that stays within the root must not block directory hashing.
func TestRecordArtifactsDirHashAllowsInTreeSymlink(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target.txt")
	require.NoError(t, os.WriteFile(target, []byte("in-tree-target"), 0o644))

	hashedDir := filepath.Join(base, "hasheddir")
	require.NoError(t, os.Mkdir(hashedDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(hashedDir, "real.txt"), []byte("in-tree"), 0o644))
	require.NoError(t, os.Symlink(target, filepath.Join(hashedDir, "intree.link")))

	dirHash := []glob.Glob{glob.MustCompile("hasheddir")}

	_, err := RecordArtifacts(
		base,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		dirHash,
	)
	require.NoError(t, err, "dir-hash mode must allow a hashed directory whose symlink stays within the attested root")
}
