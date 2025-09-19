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

package dsse

// Documentation provides structured documentation for the dsse package
type Documentation struct {
	Summary     string             `json:"summary" jsonschema:"title=Summary,description=Brief description of the package"`
	Description string             `json:"description" jsonschema:"title=Description,description=Detailed description of the package functionality"`
	Usage       []string           `json:"usage" jsonschema:"title=Usage,description=Common use cases and scenarios"`
	Examples    map[string]Example `json:"examples" jsonschema:"title=Examples,description=Code examples demonstrating package usage"`
}

// Example represents a code example with explanation
type Example struct {
	Description string `json:"description" jsonschema:"title=Description,description=What this example demonstrates"`
	Code        string `json:"code" jsonschema:"title=Code,description=Example code snippet"`
}

// PackageDocumentation returns the documentation for the dsse package
func PackageDocumentation() Documentation {
	return Documentation{
		Summary: "Dead Simple Signing Envelope (DSSE) implementation for witness attestations",
		Description: `The dsse package implements the DSSE specification for creating and verifying signed envelopes:
- Create DSSE envelopes with multiple signatures
- Support for X.509 certificate chains in signatures
- RFC3161 timestamp integration
- Threshold signature verification
- Pre-authentication encoding per DSSE spec
- Compatible with in-toto attestation framework`,
		Usage: []string{
			"Wrap attestations in signed DSSE envelopes",
			"Verify DSSE envelope signatures with threshold support",
			"Add trusted timestamps to signatures",
			"Include certificate chains for PKI verification",
			"Create portable signed attestation bundles",
		},
		Examples: map[string]Example{
			"create_envelope": {
				Description: "Create a DSSE envelope with signature",
				Code: `// Create payload
payload := []byte("{\"_type\": \"https://in-toto.io/Statement/v0.1\", \"subject\": [...]}")

// Sign with options
envelope, err := Sign("application/vnd.in-toto+json", payload, 
    WithSigner(signer),
    WithTimestampers(timestamper),
)
if err != nil {
    log.Fatal(err)
}

// Envelope now contains signed payload`,
			},
			"verify_envelope": {
				Description: "Verify a DSSE envelope with threshold",
				Code: `// Define verifiers
verifiers := []cryptoutil.Verifier{verifier1, verifier2}

// Verify with threshold of 2
results, err := Verify(envelope, 
    WithVerifiers(verifiers...),
    WithThreshold(2),
    WithRoots(rootCerts),
)
if err != nil {
    log.Fatal(err)
}

// Check verification results
fmt.Printf("Passed verifiers: %d\n", len(results.PassedVerifiers))`,
			},
			"add_timestamp": {
				Description: "Add RFC3161 timestamp to signature",
				Code: `// Create timestamper
timestamper := timestamp.NewRFC3161Timestamper(
    timestamp.WithUrl("https://freetsa.org/tsr"),
)

// Sign with timestamp
envelope, err := Sign(payloadType, payload,
    WithSigner(signer),
    WithTimestampers(timestamper),
)

// Envelope signatures now include timestamps`,
			},
		},
	}
}

// EnvelopeDocumentation provides documentation specific to DSSE envelopes
type EnvelopeDocumentation struct {
	Overview      string   `json:"overview" jsonschema:"title=Overview,description=Overview of DSSE envelope structure"`
	PayloadTypes  []string `json:"payloadTypes" jsonschema:"title=Payload Types,description=Common payload types used with DSSE"`
	SignatureInfo []string `json:"signatureInfo" jsonschema:"title=Signature Info,description=Information about DSSE signatures"`
}

// GetEnvelopeDocumentation returns documentation for DSSE envelopes
func GetEnvelopeDocumentation() EnvelopeDocumentation {
	return EnvelopeDocumentation{
		Overview: "DSSE envelopes provide a simple, secure way to sign arbitrary data with support for multiple signatures and additional metadata",
		PayloadTypes: []string{
			"application/vnd.in-toto+json - In-toto attestation statements",
			"application/json - Generic JSON payloads",
			"text/plain - Plain text payloads",
		},
		SignatureInfo: []string{
			"Each signature includes a key identifier",
			"Signatures can include X.509 certificate chains",
			"RFC3161 timestamps provide time proof",
			"Multiple signatures enable threshold verification",
		},
	}
}
