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

//go:build unix

package cryptoutil

import (
	"crypto"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsHashableFile_FIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))

	f, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	require.NoError(t, err)
	defer f.Close()

	hashable, err := isHashableFile(f)
	require.NoError(t, err)
	require.False(t, hashable)

	ds, err := CalculateDigestSetFromFile(fifo, []DigestValue{{Hash: crypto.SHA256}})
	require.ErrorContains(t, err, "not a hashable file")
	require.Equal(t, DigestSet{}, ds)
}
