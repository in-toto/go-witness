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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/gobwas/glob"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/stretchr/testify/require"
)

func BenchmarkRecordArtifacts(b *testing.B) {
	scenarios := []struct {
		name     string
		numFiles int
		fileSize int
	}{
		{"Small_10files_1KB", 10, 1024},
		{"Medium_100files_1KB", 100, 1024},
		{"Large_1000files_1KB", 1000, 1024},
		{"XLarge_5000files_1KB", 5000, 1024},
		{"Medium_100files_1MB", 100, 1024 * 1024},
	}

	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			benchmarkRecordArtifacts(b, sc.numFiles, sc.fileSize)
		})
	}
}

func benchmarkRecordArtifacts(b *testing.B, numFiles, fileSize int) {
	b.ReportAllocs()

	// Setup: Create test files (not timed)
	dir := b.TempDir()
	for i := range numFiles {
		fileName := filepath.Join(dir, fmt.Sprintf("file_%d", i))
		content := make([]byte, fileSize)
		for j := range content {
			content[j] = byte(i + j)
		}
		if err := os.WriteFile(fileName, content, os.ModePerm); err != nil {
			b.Fatal(err)
		}
	}

	dirHash := make([]glob.Glob, 0)
	digestValues := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}

	// Reset timer to exclude setup
	b.ResetTimer()

	var totalFiles int
	var totalBytes int64

	// Run benchmark
	for b.Loop() {
		artifacts, err := RecordArtifacts(
			dir,
			map[string]cryptoutil.DigestSet{},
			digestValues,
			map[string]struct{}{},
			false,
			map[string]bool{},
			dirHash,
		)
		if err != nil {
			b.Fatal(err)
		}

		fileCount := len(artifacts)
		totalFiles += fileCount
		totalBytes += int64(fileCount * fileSize)
	}

	b.StopTimer()

	avgFilesPerOp := float64(totalFiles) / float64(b.N)
	avgBytesPerOp := float64(totalBytes) / float64(b.N)

	b.ReportMetric(avgBytesPerOp/1024/1024, "MB/op")
	b.ReportMetric(avgFilesPerOp/(b.Elapsed().Seconds()/float64(b.N)), "files/sec")
	b.ReportMetric((avgBytesPerOp/1024/1024)/(b.Elapsed().Seconds()/float64(b.N)), "MB/sec")
}

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
