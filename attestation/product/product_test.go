// Copyright 2021 The Witness Contributors
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

package product

import (
	"archive/tar"
	"bytes"
	"crypto"
	"os"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
	"github.com/testifysec/go-witness/attestation"
	"github.com/testifysec/go-witness/cryptoutil"
)

func Test_fromDigestMap(t *testing.T) {

	testDigest, err := cryptoutil.CalculateDigestSetFromBytes([]byte("test"), []crypto.Hash{crypto.SHA256})
	if err != nil {
		t.Errorf("Failed to calculate digest set from bytes: %v", err)
	}

	testDigestSet := make(map[string]cryptoutil.DigestSet)
	testDigestSet["test"] = testDigest

	result := fromDigestMap(testDigestSet)

	if len(result) != 1 {
		t.Errorf("Expected 1 product, got %d", len(result))
	}

	if result["test"].Digest.Equal(testDigest) == false {
		t.Errorf("Expected digest set to be %v, got %v", testDigest, result["test"])
	}

	t.Logf("Result: %v", spew.Sdump(result["test"]))
	t.Logf("Expected: %v", spew.Sdump(testDigest))
}

func TestAttestor_Name(t *testing.T) {
	a := New()
	if a.Name() != Name {
		t.Errorf("Expected Name to be %s, got %s", Name, a.Name())
	}
}

func TestAttestor_Type(t *testing.T) {
	a := New()
	if a.Type() != Type {
		t.Errorf("Expected Type to be %s, got %s", Type, a.Type())
	}
}

func TestAttestor_RunType(t *testing.T) {
	a := New()
	if a.RunType() != RunType {
		t.Errorf("Expected RunType to be %s, got %s", RunType, a.RunType())
	}
}

func TestAttestor_Attest(t *testing.T) {
	a := New()

	testDigest, err := cryptoutil.CalculateDigestSetFromBytes([]byte("test"), []crypto.Hash{crypto.SHA256})
	if err != nil {
		t.Errorf("Failed to calculate digest set from bytes: %v", err)
	}

	testDigestSet := make(map[string]cryptoutil.DigestSet)
	testDigestSet["test"] = testDigest

	a.baseArtifacts = testDigestSet

	ctx, err := attestation.NewContext([]attestation.Attestor{a})
	require.NoError(t, err)
	err = a.Attest(ctx)
	require.NoError(t, err)
}

func TestGetFileContentType(t *testing.T) {
	// Create a temporary directory for the test
	tempDir := t.TempDir()

	// Create a temporary text file.
	textFile, err := os.CreateTemp(tempDir, "test-*.txt")
	require.NoError(t, err)
	defer os.Remove(textFile.Name())
	_, err = textFile.WriteString("This is a test file.")
	require.NoError(t, err)

	// Create a temporary PDF file with extension.
	pdfFile, err := os.CreateTemp(tempDir, "test-*")
	require.NoError(t, err)
	defer os.Remove(pdfFile.Name())

	//write to pdf so it has correct file signature 25 50 44 46 2D
	_, err = pdfFile.WriteAt([]byte{0x25, 0x50, 0x44, 0x46, 0x2D}, 0)

	require.NoError(t, err)

	// Create a temporary tar file with no extension.
	tarFile, err := os.CreateTemp(tempDir, "test-*")
	require.NoError(t, err)
	defer os.Remove(tarFile.Name())
	tarBuffer := new(bytes.Buffer)
	writer := tar.NewWriter(tarBuffer)
	header := &tar.Header{
		Name: "test.txt",
		Size: int64(len("This is a test file.")),
	}
	require.NoError(t, writer.WriteHeader(header))
	_, err = writer.Write([]byte("This is a test file."))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	_, err = tarFile.Write(tarBuffer.Bytes())
	require.NoError(t, err)

	// Open the temporary tar file using os.Open.
	tarFile, err = os.Open(tarFile.Name())
	require.NoError(t, err)

	// Define the test cases.
	tests := []struct {
		name     string
		file     *os.File
		expected string
	}{
		{"text file with extension", textFile, "text/plain; charset=utf-8"},
		{"PDF file with no extension", pdfFile, "application/pdf"},
		{"tar file with no extension", tarFile, "application/x-tar"},
	}

	// Run the test cases.
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			contentType, err := getFileContentType(test.file)
			require.NoError(t, err)
			require.Equal(t, test.expected, contentType)
		})
	}
}
