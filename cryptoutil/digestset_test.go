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

package cryptoutil

import (
	"crypto"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDigestSetEqualRejectsHashDowngrade(t *testing.T) {
	sha256 := DigestValue{Hash: crypto.SHA256}
	sha1 := DigestValue{Hash: crypto.SHA1}

	// The full digest set is described by both a strong (SHA-256) and a weak (SHA-1) hash.
	full := DigestSet{
		sha256: "3b1f2e8c9d4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f9012345abcd",
		sha1:   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
	}

	// A different artifact that omits the strong hash and shares only the weak one.
	weakOnly := DigestSet{
		sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
	}

	// Equality must not silently downgrade to the weakest shared hash: a set lacking the strong
	// digest must not compare equal to one that has it.
	require.False(t, full.Equal(weakOnly),
		"DigestSet.Equal downgraded to the weakest shared hash; a SHA-1-only digest compared equal to a SHA-256 artifact")
}

func TestDigestSetEqual_EdgeCases(t *testing.T) {
	sha256a := DigestValue{Hash: crypto.SHA256}
	gitoidSHA256 := DigestValue{Hash: crypto.SHA256, GitOID: true} // same 32-byte size as sha256
	sha1a := DigestValue{Hash: crypto.SHA1}

	const (
		x256 = "3b1f2e8c9d4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f9012345abcd"
		y256 = "0000000000000000000000000000000000000000000000000000000000000000"
		g256 = "gitoid:sha256:1111111111111111111111111111111111111111111111111111111111111111"
		w1   = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	)

	tests := []struct {
		name  string
		a, b  DigestSet
		equal bool
	}{
		{"both empty are not equal", DigestSet{}, DigestSet{}, false},
		{"no shared algorithm", DigestSet{sha256a: x256}, DigestSet{sha1a: w1}, false},
		{"same single strong digest agrees", DigestSet{sha256a: x256}, DigestSet{sha256a: x256}, true},
		{"strongest digest disagrees", DigestSet{sha256a: x256}, DigestSet{sha256a: y256}, false},
		{"weaker-side superset still equal on strong", DigestSet{sha256a: x256}, DigestSet{sha256a: x256, sha1a: w1}, true},
		{"downgrade attempt: strong omitted, weak agrees", DigestSet{sha256a: x256, sha1a: w1}, DigestSet{sha1a: w1}, false},
		{"tie at strongest size: shared sha256 agrees, gitoid omitted", DigestSet{sha256a: x256, gitoidSHA256: g256}, DigestSet{sha256a: x256}, true},
		{"tie at strongest size: shared strong disagrees", DigestSet{sha256a: x256, gitoidSHA256: g256}, DigestSet{sha256a: y256}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.equal, tt.a.Equal(tt.b))
			require.Equal(t, tt.equal, tt.b.Equal(tt.a), "Equal must be symmetric")
		})
	}
}

func TestIsHashableFile(t *testing.T) {
	regular := filepath.Join(t.TempDir(), "regular")
	require.NoError(t, os.WriteFile(regular, []byte("hello"), 0o644))

	fifo := filepath.Join(t.TempDir(), "fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))

	dir := t.TempDir()

	tests := []struct {
		name     string
		path     string
		hashable bool
	}{
		{"regular file is hashable", regular, true},
		{"directory is not hashable", dir, false},
		{"named pipe is not hashable", fifo, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.OpenFile(tt.path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
			require.NoError(t, err)
			defer f.Close()

			hashable, err := isHashableFile(f)
			require.NoError(t, err)
			require.Equal(t, tt.hashable, hashable)

			ds, err := CalculateDigestSetFromFile(tt.path, []DigestValue{{Hash: crypto.SHA256}})
			if tt.hashable {
				expected, expErr := CalculateDigestSetFromBytes([]byte("hello"), []DigestValue{{Hash: crypto.SHA256}})
				require.NoError(t, expErr)
				require.NoError(t, err)
				require.Equal(t, expected, ds)
			} else {
				require.Error(t, err)
				require.Contains(t, err.Error(), "not a hashable file")
				require.Equal(t, DigestSet{}, ds)
			}
		})
	}
}
