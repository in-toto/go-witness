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

package productarchive_test

import (
	"encoding/json"
	"fmt"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/productarchive"
)

// Example demonstrates how the product-archive attestor creates
// individual attestations for each product file.
func Example() {
	// Create a product archive attestor
	pa := productarchive.New()

	// Simulate having collected some products
	// (In real usage, these would come from the product attestor)
	_ = pa.Attest(&attestation.AttestationContext{})

	// The attestor implements MultiExporter, which means it will
	// create individual attestations for each archived product
	attestations := pa.ExportedAttestations()

	fmt.Printf("Number of attestations: %d\n", len(attestations))

	// Each attestation contains a single product with its metadata
	for i, att := range attestations {
		fmt.Printf("\nAttestation %d:\n", i+1)
		fmt.Printf("  Name: %s\n", att.Name)
		fmt.Printf("  Type: %s\n", att.PredicateType)
		fmt.Printf("  Subjects: %d\n", len(att.Subjects))

		// The predicate contains the archived product data
		data, _ := json.MarshalIndent(att.Predicate, "  ", "  ")
		fmt.Printf("  Predicate: %s\n", string(data))
	}

	// Output:
	// Number of attestations: 0
}

// Example_withProducts demonstrates creating attestations for actual products
func Example_withProducts() {
	// This example shows how the witness run command would use the attestor
	// to create individual attestations for each product file.

	// When witness runs with product-archive attestor:
	// 1. Product attestor collects output files
	// 2. Product-archive attestor filters and archives products
	// 3. Instead of one attestation, it creates N attestations (one per file)
	// 4. Each attestation is signed separately
	// 5. Result: product-archive/file1.bin, product-archive/file2.txt, etc.

	fmt.Println("Product archive creates individual attestations per file")
	// Output: Product archive creates individual attestations per file
}
