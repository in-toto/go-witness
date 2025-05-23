// Copyright 2024 The Witness Contributors
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

package productarchive

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProductArchive_Filters(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	// Create test files
	testFiles := map[string]struct {
		content  string
		mimeType string
	}{
		"test.txt":  {"hello world", "text/plain"},
		"test.json": {`{"test": true}`, "application/json"},
		"large.bin": {string(make([]byte, 200*1024*1024)), "application/octet-stream"}, // 200MB
		"README.md": {"# Test", "text/markdown"},
		"image.png": {"fake png content", "image/png"},
	}

	products := make(map[string]attestation.Product)
	for name, file := range testFiles {
		path := filepath.Join(tmpDir, name)
		err := os.WriteFile(path, []byte(file.content), 0644)
		require.NoError(t, err)

		digestSet, _ := cryptoutil.NewDigestSet(map[string]string{
			"sha256": "test-digest",
		})
		products[name] = attestation.Product{
			MimeType: file.mimeType,
			Digest:   digestSet,
		}
	}

	tests := []struct {
		name             string
		opts             []Option
		expectedProducts []string
	}{
		{
			name: "include by mime type",
			opts: []Option{
				WithIncludeMimeTypes([]string{"text/plain", "application/json"}),
			},
			expectedProducts: []string{"test.txt", "test.json"},
		},
		{
			name: "exclude by mime type",
			opts: []Option{
				WithExcludeMimeTypes([]string{"image/png"}),
			},
			expectedProducts: []string{"test.txt", "test.json", "README.md"},
		},
		{
			name: "include by glob",
			opts: []Option{
				WithIncludeGlob([]string{"*.txt", "*.md"}),
			},
			expectedProducts: []string{"test.txt", "README.md"},
		},
		{
			name: "exclude by glob",
			opts: []Option{
				WithExcludeGlob([]string{"README.*"}),
			},
			expectedProducts: []string{"test.txt", "test.json", "image.png"},
		},
		{
			name: "max file size",
			opts: []Option{
				WithMaxFileSize(1024 * 1024), // 1MB
			},
			expectedProducts: []string{"test.txt", "test.json", "README.md", "image.png"},
		},
		{
			name: "combined filters",
			opts: []Option{
				WithIncludeMimeTypes([]string{"text/plain", "text/markdown"}),
				WithExcludeGlob([]string{"README.*"}),
			},
			expectedProducts: []string{"test.txt"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pa := New(tt.opts...)

			// Create a mock product attestor
			mockProducer := &mockProductAttestor{products: products}

			// Create attestation context and run all attestors
			ctx, err := attestation.NewContext("test", []attestation.Attestor{mockProducer, pa}, attestation.WithWorkingDir(tmpDir))
			require.NoError(t, err)

			// Run all attestors through the context - this will populate products
			err = ctx.RunAttestors()
			require.NoError(t, err)

			archivedNames := make([]string, 0, len(pa.products))
			for _, p := range pa.products {
				archivedNames = append(archivedNames, p.Name)
			}

			assert.ElementsMatch(t, tt.expectedProducts, archivedNames)
		})
	}
}

func TestProductArchive_Export(t *testing.T) {
	pa := New()
	assert.True(t, pa.Export())
}

func TestProductArchive_Schema(t *testing.T) {
	pa := New()
	schema := pa.Schema()
	assert.NotNil(t, schema)
}

func TestProductArchive_MultiExporter(t *testing.T) {
	pa := New()
	digest1, _ := cryptoutil.NewDigestSet(map[string]string{
		"sha256": "abc123",
	})
	digest2, _ := cryptoutil.NewDigestSet(map[string]string{
		"sha256": "def456",
	})
	pa.products = []ArchivedProduct{
		{
			Name:     "test.txt",
			Path:     "/tmp/test.txt",
			MimeType: "text/plain",
			Digest:   digest1,
			Content:  []byte("test content"),
			Metadata: FileMetadata{Size: 12},
		},
		{
			Name:     "test.json",
			Path:     "/tmp/test.json",
			MimeType: "application/json",
			Digest:   digest2,
			Content:  []byte(`{"test": true}`),
			Metadata: FileMetadata{Size: 14},
		},
	}

	// Test Export returns true
	assert.True(t, pa.Export())

	// Get exported attestations
	attestations := pa.ExportedAttestations()
	assert.Len(t, attestations, 2)

	// Verify first attestation
	att1 := attestations[0]
	assert.Equal(t, "test.txt", att1.Name)
	assert.Equal(t, Type, att1.PredicateType)
	assert.Len(t, att1.Subjects, 1)
	assert.NotNil(t, att1.Subjects["file:test.txt"])

	// Verify predicate contains only one product
	pred1, ok := att1.Predicate.(struct {
		Products []ArchivedProduct `json:"products"`
	})
	assert.True(t, ok)
	assert.Len(t, pred1.Products, 1)
	assert.Equal(t, "test.txt", pred1.Products[0].Name)

	// Verify second attestation
	att2 := attestations[1]
	assert.Equal(t, "test.json", att2.Name)
	assert.Len(t, att2.Subjects, 1)
	assert.NotNil(t, att2.Subjects["file:test.json"])
}

func TestProductArchive_BinaryFiles(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	// Create test binary file with known content
	binaryContent := make([]byte, 1024) // 1KB binary file
	for i := range binaryContent {
		binaryContent[i] = byte(i % 256)
	}

	binaryPath := filepath.Join(tmpDir, "test.bin")
	err := os.WriteFile(binaryPath, binaryContent, 0644)
	require.NoError(t, err)

	// Create a large binary file that exceeds the limit
	largeBinaryContent := make([]byte, 1024*1024) // 1MB
	largeBinaryPath := filepath.Join(tmpDir, "large.bin")
	err = os.WriteFile(largeBinaryPath, largeBinaryContent, 0644)
	require.NoError(t, err)

	// Create products map
	digestSet, _ := cryptoutil.NewDigestSet(map[string]string{
		"sha256": "test-binary-digest",
	})
	largeDigestSet, _ := cryptoutil.NewDigestSet(map[string]string{
		"sha256": "test-large-binary-digest",
	})

	products := map[string]attestation.Product{
		"test.bin": {
			MimeType: "application/octet-stream",
			Digest:   digestSet,
		},
		"large.bin": {
			MimeType: "application/octet-stream",
			Digest:   largeDigestSet,
		},
	}

	// Test with different size limits
	tests := []struct {
		name          string
		maxFileSize   int64
		expectedFiles []string
		checkContent  bool
	}{
		{
			name:          "include small binary",
			maxFileSize:   10 * 1024, // 10KB limit
			expectedFiles: []string{"test.bin"},
			checkContent:  true,
		},
		{
			name:          "include all binaries",
			maxFileSize:   2 * 1024 * 1024, // 2MB limit
			expectedFiles: []string{"test.bin", "large.bin"},
			checkContent:  false, // Don't check content for large file test
		},
		{
			name:          "exclude large binary",
			maxFileSize:   512 * 1024, // 512KB limit
			expectedFiles: []string{"test.bin"},
			checkContent:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pa := New(WithMaxFileSize(tt.maxFileSize))

			// Create mock producer and context
			mockProducer := &mockProductAttestor{products: products}
			ctx, err := attestation.NewContext("test", []attestation.Attestor{mockProducer, pa}, attestation.WithWorkingDir(tmpDir))
			require.NoError(t, err)

			// Run attestors
			err = ctx.RunAttestors()
			require.NoError(t, err)

			// Check results
			assert.Len(t, pa.products, len(tt.expectedFiles))

			foundFiles := make(map[string]bool)
			for _, p := range pa.products {
				foundFiles[p.Name] = true

				// Verify binary content was included and is correct
				if tt.checkContent && p.Name == "test.bin" {
					assert.NotNil(t, p.Content)
					assert.Equal(t, binaryContent, p.Content)
				}
			}

			for _, expectedFile := range tt.expectedFiles {
				assert.True(t, foundFiles[expectedFile], "Expected file %s not found", expectedFile)
			}
		})
	}
}

func TestProductArchive_JSONEncoding(t *testing.T) {
	// Test that binary content is properly base64 encoded in JSON
	binaryContent := []byte{0xFF, 0xFE, 0xFD, 0x00, 0x01, 0x02, 0x03}

	digest, _ := cryptoutil.NewDigestSet(map[string]string{
		"sha256": "test-digest",
	})

	pa := New()
	pa.products = []ArchivedProduct{
		{
			Name:     "binary.dat",
			Path:     "/tmp/binary.dat",
			MimeType: "application/octet-stream",
			Digest:   digest,
			Content:  binaryContent,
			Metadata: FileMetadata{
				Size: int64(len(binaryContent)),
			},
		},
	}

	// Marshal to JSON
	jsonData, err := pa.MarshalJSON()
	require.NoError(t, err)

	// Check that it's valid JSON
	var result map[string]interface{}
	err = json.Unmarshal(jsonData, &result)
	require.NoError(t, err)

	// Verify the content is base64 encoded
	products := result["products"].([]interface{})
	product := products[0].(map[string]interface{})
	contentStr := product["content"].(string)

	// Decode the base64
	decodedContent, err := base64.StdEncoding.DecodeString(contentStr)
	require.NoError(t, err)

	// Verify it matches original
	assert.Equal(t, binaryContent, decodedContent)
}

// mockProductAttestor is a test helper that implements the Producer interface
type mockProductAttestor struct {
	products map[string]attestation.Product
}

func (m *mockProductAttestor) Name() string {
	return "mock-product"
}

func (m *mockProductAttestor) Type() string {
	return "mock-product-type"
}

func (m *mockProductAttestor) RunType() attestation.RunType {
	return attestation.ProductRunType
}

func (m *mockProductAttestor) Attest(ctx *attestation.AttestationContext) error {
	return nil
}

func (m *mockProductAttestor) Schema() *jsonschema.Schema {
	return &jsonschema.Schema{}
}

func (m *mockProductAttestor) Products() map[string]attestation.Product {
	return m.products
}

func TestProductArchive_Metadata(t *testing.T) {
	// Create a temporary directory and file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "metadata-test.txt")
	content := []byte("test content for metadata")
	err := os.WriteFile(testFile, content, 0644)
	require.NoError(t, err)

	// Create a symlink
	symlinkPath := filepath.Join(tmpDir, "test-link")
	err = os.Symlink(testFile, symlinkPath)
	require.NoError(t, err)

	// Get file info
	info, err := os.Stat(testFile)
	require.NoError(t, err)

	// Get symlink info
	linkInfo, err := os.Lstat(symlinkPath)
	require.NoError(t, err)

	// Collect metadata
	metadata, err := collectFileMetadata(testFile, info)
	require.NoError(t, err)

	// Verify basic metadata
	assert.Equal(t, int64(len(content)), metadata.Size)
	assert.Equal(t, uint32(0644), metadata.Mode&0777) // Check permission bits
	assert.True(t, metadata.IsRegular)
	assert.False(t, metadata.IsDir)
	assert.False(t, metadata.IsSymlink)
	assert.Greater(t, metadata.ModTime, int64(0))

	// Platform-specific checks
	if metadata.UID != 0 || metadata.GID != 0 {
		// We got platform-specific data
		assert.Greater(t, metadata.Inode, uint64(0))
		assert.Greater(t, metadata.Nlink, uint64(0))
	}

	// Test symlink metadata
	linkMetadata, err := collectFileMetadata(symlinkPath, linkInfo)
	require.NoError(t, err)
	assert.True(t, linkMetadata.IsSymlink)
	assert.Equal(t, testFile, linkMetadata.LinkTarget)
}
