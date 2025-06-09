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

package cryptoutil

// Documentation provides structured documentation for the cryptoutil package
type Documentation struct {
	Summary     string              `json:"summary" jsonschema:"title=Summary,description=Brief description of the package"`
	Description string              `json:"description" jsonschema:"title=Description,description=Detailed description of the package functionality"`
	Usage       []string            `json:"usage" jsonschema:"title=Usage,description=Common use cases and scenarios"`
	Examples    map[string]Example  `json:"examples" jsonschema:"title=Examples,description=Code examples demonstrating package usage"`
}

// Example represents a code example with explanation
type Example struct {
	Description string `json:"description" jsonschema:"title=Description,description=What this example demonstrates"`
	Code        string `json:"code" jsonschema:"title=Code,description=Example code snippet"`
}

// PackageDocumentation returns the documentation for the cryptoutil package
func PackageDocumentation() Documentation {
	return Documentation{
		Summary: "Cryptographic utilities for digest calculation, signature verification, and key handling",
		Description: `The cryptoutil package provides core cryptographic functionality for witness, including:
- DigestSet: Calculate and manage multiple digests for files and data
- Signature creation and verification with multiple algorithms (RSA, ECDSA, ED25519)
- X.509 certificate handling and verification
- Git Object ID (gitoid) calculation
- Directory hashing compatible with Go module tooling`,
		Usage: []string{
			"Calculate cryptographic digests of files and directories",
			"Create and verify digital signatures",
			"Handle X.509 certificates and public keys",
			"Generate attestation signatures with timestamp support",
			"Verify attestation signatures against policies",
		},
		Examples: map[string]Example{
			"calculate_digest": {
				Description: "Calculate SHA256 digest of a file",
				Code: `// Calculate digest of a file
hashes := []DigestValue{{Hash: crypto.SHA256}}
digestSet, err := CalculateDigestSetFromFile("myfile.txt", hashes)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("SHA256: %s\n", digestSet[DigestValue{Hash: crypto.SHA256}])`,
			},
			"verify_signature": {
				Description: "Verify a signature using a public key",
				Code: `// Load public key and verify signature
pubKeyPEM, _ := os.ReadFile("public.pem")
verifier, err := NewVerifierFromPEM(pubKeyPEM)
if err != nil {
    log.Fatal(err)
}

message := []byte("hello world")
signature, _ := base64.StdEncoding.DecodeString("...")
err = verifier.Verify(message, signature)`,
			},
			"create_signer": {
				Description: "Create a signer from a private key",
				Code: `// Load private key and create signer
keyPEM, _ := os.ReadFile("private.pem")
signer, err := NewSignerFromPEM(keyPEM)
if err != nil {
    log.Fatal(err)
}

message := []byte("data to sign")
signature, err := signer.Sign(bytes.NewReader(message))`,
			},
		},
	}
}

// DigestSetDocumentation provides documentation specific to DigestSet usage
type DigestSetDocumentation struct {
	Overview           string   `json:"overview" jsonschema:"title=Overview,description=Overview of DigestSet functionality"`
	SupportedAlgorithms []string `json:"supportedAlgorithms" jsonschema:"title=Supported Algorithms,description=List of supported hash algorithms"`
	SpecialFormats     []string `json:"specialFormats" jsonschema:"title=Special Formats,description=Special digest formats like gitoid and dirhash"`
}

// GetDigestSetDocumentation returns documentation for DigestSet
func GetDigestSetDocumentation() DigestSetDocumentation {
	return DigestSetDocumentation{
		Overview: "DigestSet manages multiple cryptographic digests for a single artifact, allowing verification with different hash algorithms",
		SupportedAlgorithms: []string{
			"SHA256 - Default and recommended hash algorithm",
			"SHA1 - Legacy support, not recommended for new uses",
			"SHA384 - Alternative SHA-2 variant",
			"SHA512 - Maximum security SHA-2 variant",
		},
		SpecialFormats: []string{
			"gitoid - Git Object ID format for compatibility with git",
			"dirhash - Directory hash using Go module dirhash algorithm",
		},
	}
}