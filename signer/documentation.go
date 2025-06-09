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

package signer

// Documentation provides structured documentation for the signer package
type Documentation struct {
	Summary     string              `json:"summary" jsonschema:"title=Summary,description=Brief description of the package"`
	Description string              `json:"description" jsonschema:"title=Description,description=Detailed description of the package functionality"`
	Usage       []string            `json:"usage" jsonschema:"title=Usage,description=Common use cases and scenarios"`
	Examples    map[string]Example  `json:"examples" jsonschema:"title=Examples,description=Code examples demonstrating package usage"`
	Providers   map[string]ProviderDoc `json:"providers" jsonschema:"title=Providers,description=Documentation for available signer providers"`
}

// Example represents a code example with explanation
type Example struct {
	Description string `json:"description" jsonschema:"title=Description,description=What this example demonstrates"`
	Code        string `json:"code" jsonschema:"title=Code,description=Example code snippet"`
}

// ProviderDoc documents a specific signer provider
type ProviderDoc struct {
	Summary     string            `json:"summary" jsonschema:"title=Summary,description=Brief description of the provider"`
	Options     map[string]string `json:"options" jsonschema:"title=Options,description=Configuration options for this provider"`
	Example     string            `json:"example" jsonschema:"title=Example,description=Example usage of this provider"`
}

// PackageDocumentation returns the documentation for the signer package
func PackageDocumentation() Documentation {
	return Documentation{
		Summary: "Extensible signing provider framework for witness attestations",
		Description: `The signer package provides a pluggable system for different signing mechanisms:
- File-based signing with local private keys
- Cloud KMS integration (AWS, GCP, Azure)
- Sigstore keyless signing with Fulcio
- SPIFFE/SPIRE workload identity signing
- HashiCorp Vault integration
- Extensible registry for custom providers`,
		Usage: []string{
			"Sign attestations with various key management systems",
			"Abstract signing implementation from attestation logic",
			"Support both key-based and keyless signing workflows",
			"Enable workload identity-based signing in cloud environments",
			"Integrate with existing PKI infrastructure",
		},
		Examples: map[string]Example{
			"file_signer": {
				Description: "Create a file-based signer",
				Code: `// Create file signer
provider, err := NewSignerProvider("file",
    file.WithKeyPath("/path/to/private.key"),
    file.WithCertPath("/path/to/cert.pem"),
)
if err != nil {
    log.Fatal(err)
}

// Get signer
signer, err := provider.Signer(ctx)
if err != nil {
    log.Fatal(err)
}

// Sign data
signature, err := signer.Sign(bytes.NewReader(data))`,
			},
			"fulcio_keyless": {
				Description: "Use Sigstore keyless signing",
				Code: `// Create Fulcio signer
provider, err := NewSignerProvider("fulcio",
    fulcio.WithFulcioURL("https://fulcio.sigstore.dev"),
    fulcio.WithOIDCIssuer("https://oauth2.sigstore.dev/auth"),
    fulcio.WithOIDCClientID("sigstore"),
)

// Get signer (will trigger OIDC flow)
signer, err := provider.Signer(ctx)`,
			},
			"aws_kms": {
				Description: "Use AWS KMS for signing",
				Code: `// Create AWS KMS signer
provider, err := NewSignerProvider("kms",
    kms.WithRef("awskms:///arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"),
    kms.WithHash("SHA256"),
)

signer, err := provider.Signer(ctx)`,
			},
		},
		Providers: map[string]ProviderDoc{
			"file": {
				Summary: "Signs with private keys stored in local files",
				Options: map[string]string{
					"key-path":          "Path to private key file (PEM format)",
					"cert-path":         "Path to certificate file (optional)",
					"intermediate-paths": "Paths to intermediate certificates (optional)",
				},
				Example: "witness run -s build --signer-file-key-path key.pem -- make",
			},
			"fulcio": {
				Summary: "Sigstore keyless signing using OIDC identity",
				Options: map[string]string{
					"fulcio-url":     "Fulcio server URL",
					"oidc-issuer":    "OIDC token issuer URL",
					"oidc-client-id": "OIDC client ID",
					"token":          "Pre-obtained OIDC token",
					"token-path":     "Path to file containing OIDC token",
				},
				Example: "witness run -s build --signer-fulcio-url https://fulcio.sigstore.dev -- make",
			},
			"kms": {
				Summary: "Cloud KMS signing (AWS, GCP, Azure)",
				Options: map[string]string{
					"ref":         "KMS key reference URI",
					"hash-algo":   "Hash algorithm (SHA256, SHA384, SHA512)",
					"key-version": "Specific key version to use",
				},
				Example: "witness run -s build --signer-kms-ref gcpkms://projects/myproject/locations/global/keyRings/myring/cryptoKeys/mykey -- make",
			},
			"spiffe": {
				Summary: "SPIFFE/SPIRE workload identity signing",
				Options: map[string]string{
					"socket-path": "Path to SPIFFE Workload API socket",
				},
				Example: "witness run -s build --signer-spiffe-socket-path /tmp/spire-agent/public/api.sock -- make",
			},
			"vault": {
				Summary: "HashiCorp Vault signing",
				Options: map[string]string{
					"url":       "Vault server URL",
					"token":     "Vault authentication token",
					"pki-path":  "Path to PKI secrets engine",
					"role":      "PKI role name",
				},
				Example: "witness run -s build --signer-vault-url https://vault.example.com --signer-vault-token s.abc123 -- make",
			},
		},
	}
}