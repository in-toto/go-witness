// Copyright 2022 The Witness Contributors
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

func TestBrokenSymlink(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "testfile")
	require.NoError(t, os.WriteFile(testFile, []byte("some dummy data"), os.ModePerm))
	testDir := filepath.Join(dir, "testdir")
	require.NoError(t, os.Mkdir(testDir, os.ModePerm))
	testFile2 := filepath.Join(testDir, "testfile2")
	require.NoError(t, os.WriteFile(testFile2, []byte("more dummy data"), os.ModePerm))

	symTestFile := filepath.Join(dir, "symtestfile")
	require.NoError(t, os.Symlink(testFile, symTestFile))
	symTestDir := filepath.Join(dir, "symTestDir")
	require.NoError(t, os.Symlink(testDir, symTestDir))

	dirHash := make([]glob.Glob, 0)

	_, err := RecordArtifacts(dir, map[string]cryptoutil.DigestSet{}, []cryptoutil.DigestValue{{Hash: crypto.SHA256}}, map[string]struct{}{}, false, map[string]bool{}, dirHash)
	require.NoError(t, err)

	// remove the symlinks and make sure we don't get an error back
	require.NoError(t, os.RemoveAll(testDir))
	require.NoError(t, os.RemoveAll(testFile))
	_, err = RecordArtifacts(dir, map[string]cryptoutil.DigestSet{}, []cryptoutil.DigestValue{{Hash: crypto.SHA256}}, map[string]struct{}{}, false, map[string]bool{}, dirHash)
	require.NoError(t, err)
}

func TestSymlinkCycle(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "testfile")
	require.NoError(t, os.WriteFile(testFile, []byte("some dummy data"), os.ModePerm))
	symTestFile := filepath.Join(dir, "symtestfile")
	require.NoError(t, os.Symlink(testFile, symTestFile))
	symTestDir := filepath.Join(dir, "symTestDir")
	require.NoError(t, os.Symlink(dir, symTestDir))

	dirHash := make([]glob.Glob, 0)

	// if a symlink cycle weren't properly handled this would be an infinite loop
	_, err := RecordArtifacts(dir, map[string]cryptoutil.DigestSet{}, []cryptoutil.DigestValue{{Hash: crypto.SHA256}}, map[string]struct{}{}, false, map[string]bool{}, dirHash)
	require.NoError(t, err)
}

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
