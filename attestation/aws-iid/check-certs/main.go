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

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/html"
)

const awsDocsURL = "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/regions-certs.html"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <go-certs-file>\n", os.Args[0])
		os.Exit(1)
	}

	goCertsFile := os.Args[1]

	// Download and parse AWS documentation
	fmt.Println("Downloading AWS documentation...")
	resp, err := http.Get(awsDocsURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error downloading documentation: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Error: HTTP status %d\n", resp.StatusCode)
		os.Exit(1)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading response: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Parsing HTML and extracting RSA certificates by region...")
	docsCerts := extractRSACertificatesByRegion(string(body))
	fmt.Printf("Found %d RSA certificates in AWS docs\n", len(docsCerts))

	// Parse Go file
	fmt.Println("\nParsing aws-certs.go...")
	goCerts, err := parseGoCertsFile(goCertsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing Go file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Found %d certificates in Go file\n", len(goCerts))

	// Compare certificates
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("COMPARISON RESULTS")
	fmt.Println(strings.Repeat("=", 80))

	compareCertificates(docsCerts, goCerts)
}

// extractRSACertificatesByRegion parses the HTML and extracts RSA certificates by region
func extractRSACertificatesByRegion(htmlContent string) map[string]string {
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing HTML: %v\n", err)
		return nil
	}

	certificates := make(map[string]string)
	var currentRegion string

	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		// Check if this is an expandable section with a region header
		if n.Type == html.ElementNode && n.Data == "awsui-expandable-section" {
			for _, attr := range n.Attr {
				if attr.Key == "header" {
					// Extract region code from header like "US East (N. Virginia) — us-east-1"
					currentRegion = extractRegionCode(attr.Val)
					break
				}
			}
		}

		// Check if this is a dd element with tab-id="rsa"
		if n.Type == html.ElementNode && n.Data == "dd" && currentRegion != "" {
			for _, attr := range n.Attr {
				if attr.Key == "tab-id" && attr.Val == "rsa" {
					// Extract text content from this node and its children
					text := getTextContent(n)
					// Extract certificate from the text
					certs := extractCertificatesFromText(text)
					if len(certs) > 0 {
						certificates[currentRegion] = normalizeCert(certs[0])
					}
					return
				}
			}
		}

		// Traverse children
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}

	traverse(doc)
	return certificates
}

// extractRegionCode extracts the region code from a header string
// e.g., "US East (N. Virginia) — us-east-1" -> "us-east-1"
func extractRegionCode(header string) string {
	// Look for pattern "— region-code"
	parts := strings.Split(header, "—")
	if len(parts) >= 2 {
		return strings.TrimSpace(parts[len(parts)-1])
	}
	return ""
}

// getTextContent recursively extracts all text content from a node
func getTextContent(n *html.Node) string {
	if n.Type == html.TextNode {
		return n.Data
	}

	var text string
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		text += getTextContent(c)
	}
	return text
}

// extractCertificatesFromText extracts certificate blocks from text
func extractCertificatesFromText(text string) []string {
	// Regular expression to match certificate blocks
	certRegex := regexp.MustCompile(`-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----`)
	matches := certRegex.FindAllString(text, -1)

	var certificates []string
	for _, match := range matches {
		// Clean up the certificate (normalize whitespace)
		cert := strings.TrimSpace(match)
		certificates = append(certificates, cert)
	}

	return certificates
}

// normalizeCert normalizes a certificate for comparison
func normalizeCert(cert string) string {
	// Remove all whitespace and normalize line endings
	return strings.Join(strings.Fields(cert), "\n")
}

// certHash returns a hash of a certificate for comparison
func certHash(cert string) string {
	// Normalize by removing all whitespace
	normalized := strings.ReplaceAll(cert, "\n", "")
	normalized = strings.ReplaceAll(normalized, "\r", "")
	normalized = strings.ReplaceAll(normalized, " ", "")
	normalized = strings.ReplaceAll(normalized, "\t", "")

	hash := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(hash[:])
}

// parseGoCertsFile parses the aws-certs.go file and extracts region->cert mappings
func parseGoCertsFile(filename string) (map[string]string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	certs := make(map[string]string)

	// Regular expression to match map entries like:
	// "region-name": `-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----`,
	entryRegex := regexp.MustCompile(`"([^"]+)":\s*` + "`" + `(-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----)` + "`")
	matches := entryRegex.FindAllStringSubmatch(string(content), -1)

	for _, match := range matches {
		if len(match) >= 3 {
			region := match[1]
			cert := normalizeCert(match[2])
			certs[region] = cert
		}
	}

	return certs, nil
}

// compareCertificates compares certificates from AWS docs and Go file
func compareCertificates(docsCerts, goCerts map[string]string) {
	// Get all unique regions
	allRegions := make(map[string]bool)
	for region := range docsCerts {
		allRegions[region] = true
	}
	for region := range goCerts {
		allRegions[region] = true
	}

	// Sort regions for consistent output
	regions := make([]string, 0, len(allRegions))
	for region := range allRegions {
		regions = append(regions, region)
	}
	sort.Strings(regions)

	var matching, missingInGo, missingInDocs, different []string

	for _, region := range regions {
		docsCert, inDocs := docsCerts[region]
		goCert, inGo := goCerts[region]

		if !inDocs {
			missingInDocs = append(missingInDocs, region)
		} else if !inGo {
			missingInGo = append(missingInGo, region)
		} else {
			// Compare certificates
			if certHash(docsCert) == certHash(goCert) {
				matching = append(matching, region)
			} else {
				different = append(different, region)
			}
		}
	}

	// Print results
	fmt.Printf("\n✓ MATCHING: %d regions\n", len(matching))
	if len(matching) > 0 {
		for _, region := range matching {
			fmt.Printf("  - %s\n", region)
		}
	}

	if len(missingInGo) > 0 {
		fmt.Printf("\n⚠ MISSING IN GO FILE: %d regions\n", len(missingInGo))
		fmt.Println("  These regions are in AWS docs but not in aws-certs.go:")
		for _, region := range missingInGo {
			fmt.Printf("  - %s\n", region)
		}
	}

	if len(missingInDocs) > 0 {
		fmt.Printf("\n⚠ MISSING IN AWS DOCS: %d regions\n", len(missingInDocs))
		fmt.Println("  These regions are in aws-certs.go but not in AWS docs:")
		for _, region := range missingInDocs {
			fmt.Printf("  - %s\n", region)
		}
	}

	if len(different) > 0 {
		fmt.Printf("\n❌ DIFFERENT CERTIFICATES: %d regions\n", len(different))
		fmt.Println("  These regions have different certificates:")
		for _, region := range different {
			fmt.Printf("  - %s\n", region)
			fmt.Printf("    Docs hash: %s\n", certHash(docsCerts[region])[:16]+"...")
			fmt.Printf("    Go hash:   %s\n", certHash(goCerts[region])[:16]+"...")
		}
	}

	// Summary
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("SUMMARY")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("Total regions in AWS docs: %d\n", len(docsCerts))
	fmt.Printf("Total regions in Go file:  %d\n", len(goCerts))
	fmt.Printf("Matching:                  %d\n", len(matching))
	fmt.Printf("Missing in Go file:        %d\n", len(missingInGo))
	fmt.Printf("Missing in AWS docs:       %d\n", len(missingInDocs))
	fmt.Printf("Different certificates:    %d\n", len(different))

	if len(missingInGo) > 0 || len(different) > 0 {
		fmt.Println("\n⚠️  WARNING: The Go file needs to be updated!")
	} else if len(missingInDocs) > 0 {
		fmt.Println("\n⚠️  WARNING: The Go file contains regions not in AWS docs!")
	} else {
		fmt.Println("\n✓ All certificates match!")
	}
}
