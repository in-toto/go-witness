// verify-test is a simple command-line tool to test offline KMS verification
// using the embedded public key feature
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/policy"
	"github.com/in-toto/go-witness/signer"

	// Import AWS KMS provider
	_ "github.com/in-toto/go-witness/signer/kms/aws"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <policy.json> <attestation.json>\n", os.Args[0])
		os.Exit(1)
	}

	policyPath := os.Args[1]
	attestationPath := os.Args[2]

	// Read the policy file
	policyData, err := os.ReadFile(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read policy file: %v\n", err)
		os.Exit(1)
	}

	// Check if it's a signed policy (DSSE envelope)
	var policyEnvelope dsse.Envelope
	if err := json.Unmarshal(policyData, &policyEnvelope); err == nil && policyEnvelope.PayloadType != "" {
		// It's a DSSE envelope - the Payload is already decoded from base64 by json.Unmarshal
		// because it's a []byte field
		policyData = policyEnvelope.Payload
		fmt.Println("Decoded signed policy envelope")
	}

	// Parse the policy
	var pol policy.Policy
	if err := json.Unmarshal(policyData, &pol); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse policy: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Policy loaded successfully\n")
	fmt.Printf("  - Steps: %d\n", len(pol.Steps))
	fmt.Printf("  - Public Keys: %d\n", len(pol.PublicKeys))

	// Print public key info
	for keyID, pk := range pol.PublicKeys {
		fmt.Printf("    - Key ID: %s\n", keyID)
		fmt.Printf("      Has embedded key: %v (%d bytes)\n", len(pk.Key) > 0, len(pk.Key))
	}

	// Create verifiers from the policy's public keys
	// This is the key test - it should work WITHOUT AWS credentials
	fmt.Println("\n=== Testing PublicKeyVerifiers (the fix) ===")
	fmt.Println("Creating verifiers from policy public keys...")
	fmt.Println("(This should succeed without AWS KMS access when embedded keys are present)")
	
	verifiers, err := pol.PublicKeyVerifiers(map[string][]func(signer.SignerProvider) (signer.SignerProvider, error){})
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n❌ Failed to create verifiers: %v\n", err)
		fmt.Fprintf(os.Stderr, "\nThis error indicates the fix is NOT working.\n")
		fmt.Fprintf(os.Stderr, "Expected: Verifiers created from embedded keys without KMS access.\n")
		os.Exit(1)
	}

	fmt.Printf("\n✅ Created %d verifiers successfully!\n", len(verifiers))
	for keyID, v := range verifiers {
		vKeyID, _ := v.KeyID()
		fmt.Printf("  - Map Key (policy KeyID): %s\n", keyID)
		fmt.Printf("    Verifier's computed KeyID: %s\n", vKeyID)
	}

	// Read the attestation file
	attestationData, err := os.ReadFile(attestationPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read attestation file: %v\n", err)
		os.Exit(1)
	}

	// Parse the attestation as a DSSE envelope
	var attestationEnvelope dsse.Envelope
	if err := json.Unmarshal(attestationData, &attestationEnvelope); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse attestation: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nAttestation loaded successfully\n")
	fmt.Printf("  - Payload Type: %s\n", attestationEnvelope.PayloadType)
	fmt.Printf("  - Signatures: %d\n", len(attestationEnvelope.Signatures))

	for i, sig := range attestationEnvelope.Signatures {
		fmt.Printf("    - Signature %d: KeyID=%s\n", i+1, sig.KeyID)
	}

	// Collect verifiers that match the signature key IDs
	var matchingVerifiers []cryptoutil.Verifier
	for _, sig := range attestationEnvelope.Signatures {
		if verifier, ok := verifiers[sig.KeyID]; ok {
			fmt.Printf("\n✅ Found matching verifier for signature key ID: %s\n", sig.KeyID)
			matchingVerifiers = append(matchingVerifiers, verifier)
		} else {
			fmt.Printf("\n❌ No verifier found for signature key ID: %s\n", sig.KeyID)
			// List available verifier key IDs
			fmt.Println("Available verifier key IDs in map:")
			for k := range verifiers {
				fmt.Printf("  - %s\n", k)
			}
		}
	}

	if len(matchingVerifiers) == 0 {
		fmt.Fprintf(os.Stderr, "\n❌ No matching verifiers found!\n")
		fmt.Fprintf(os.Stderr, "This indicates the verifiers map is not keyed by the KMS URI.\n")
		os.Exit(1)
	}

	// Verify the attestation signature using the DSSE envelope's Verify method
	fmt.Println("\n=== Verifying attestation signature ===")
	checkedVerifiers, err := attestationEnvelope.Verify(dsse.VerifyWithVerifiers(matchingVerifiers...))
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Verification FAILED: %v\n", err)
		
		// Print details about checked verifiers
		for _, cv := range checkedVerifiers {
			keyID, _ := cv.Verifier.KeyID()
			if cv.Error != nil {
				fmt.Fprintf(os.Stderr, "  - Verifier %s: ERROR: %v\n", keyID, cv.Error)
			} else {
				fmt.Printf("  - Verifier %s: OK\n", keyID)
			}
		}
		os.Exit(1)
	}

	fmt.Printf("\n✅ Verification SUCCEEDED!\n")
	fmt.Printf("Verified with %d verifier(s):\n", len(checkedVerifiers))
	for _, cv := range checkedVerifiers {
		keyID, _ := cv.Verifier.KeyID()
		fmt.Printf("  - %s\n", keyID)
	}
	
	fmt.Println("\n=== Summary ===")
	fmt.Println("The KMS offline verification fix is working correctly!")
	fmt.Println("- Embedded public key was used instead of contacting AWS KMS")
	fmt.Println("- Verifier was stored under the KMS URI key ID for functionary matching")
	fmt.Println("- Attestation signature was verified successfully")
}
