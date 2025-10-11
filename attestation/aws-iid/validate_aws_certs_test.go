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

package aws_iid

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/require"
)

const awsDocsURL = "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/regions-certs.html"

// Test_ValidateAgainstAWSDocs fetches RSA certificates from AWS official documentation
// and validates that the certificates in awsRegionCerts match the official ones.
//
// This test requires internet connectivity and will skip if AWS docs are unreachable.
func Test_ValidateAgainstAWSDocs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping AWS docs validation in short mode")
	}

	// Fetch AWS certificates
	awsCerts, err := fetchAWSRSACertificates()
	if err != nil {
		t.Skipf("unable to fetch AWS certificates (network issue?): %v", err)
	}

	t.Logf("Fetched %d RSA certificates from AWS documentation", len(awsCerts))

	// Track validation results
	var (
		matched   int
		mismatched int
		missing   []string
		govcloud  []string
	)

	// Validate each certificate in the codebase
	for region := range awsRegionCerts {
		if strings.Contains(region, "gov") {
			// GovCloud regions are not in public AWS documentation
			govcloud = append(govcloud, region)
			continue
		}

		awsCert, found := awsCerts[region]
		if !found {
			missing = append(missing, region)
			t.Errorf("Region %s: certificate exists in code but not found in AWS documentation", region)
			continue
		}

		// Parse and validate both certificates first
		codeCert, err := parseCertificate(awsRegionCerts[region])
		if err != nil {
			t.Errorf("Region %s: failed to parse certificate from code: %v", region, err)
			mismatched++
			continue
		}

		awsCertParsed, err := parseCertificate(awsCert)
		if err != nil {
			t.Errorf("Region %s: failed to parse certificate from AWS docs: %v", region, err)
			mismatched++
			continue
		}

		// Compare the actual certificate data, not just the PEM encoding
		if codeCert.Equal(awsCertParsed) {
			matched++
		} else {
			mismatched++

			// Check if the code cert is still valid (not expired)
			now := time.Now()
			isStillValid := !now.Before(codeCert.NotBefore) && !now.After(codeCert.NotAfter)

			if isStillValid {
				t.Errorf("Region %s: certificate is OUTDATED (still valid but AWS has issued a newer one)", region)
			} else {
				t.Errorf("Region %s: certificate is EXPIRED or INVALID", region)
			}

			t.Logf("  Code cert - Serial: %s, NotBefore: %s, NotAfter: %s",
				codeCert.SerialNumber.String(),
				codeCert.NotBefore.Format("2006-01-02"),
				codeCert.NotAfter.Format("2006-01-02"))
			t.Logf("  AWS cert  - Serial: %s, NotBefore: %s, NotAfter: %s",
				awsCertParsed.SerialNumber.String(),
				awsCertParsed.NotBefore.Format("2006-01-02"),
				awsCertParsed.NotAfter.Format("2006-01-02"))

			if isStillValid {
				t.Logf("  Status: Old cert still works but should be updated to latest version")
			} else {
				t.Logf("  Status: CRITICAL - Old cert is no longer valid!")
			}
		}
	}

	// Check for regions in AWS docs but missing from code
	var notInCode []string
	for region := range awsCerts {
		if _, exists := awsRegionCerts[region]; !exists {
			notInCode = append(notInCode, region)
		}
	}

	// Log summary
	t.Logf("Validation summary:")
	t.Logf("  Matched AWS docs:     %d", matched)
	t.Logf("  Mismatched:           %d", mismatched)
	t.Logf("  GovCloud (not in docs): %d", len(govcloud))
	t.Logf("  Missing from code:    %d", len(notInCode))

	if len(notInCode) > 0 {
		t.Logf("Regions in AWS docs but missing from code: %v", notInCode)
		t.Errorf("%d regions are documented by AWS but missing from awsRegionCerts", len(notInCode))
	}

	require.Equal(t, 0, mismatched, "certificates must match AWS documentation")
}

// Test_AllCertificatesValid validates that all certificates in awsRegionCerts
// are valid X.509 RSA certificates that are not expired.
func Test_AllCertificatesValid(t *testing.T) {
	for region, certPEM := range awsRegionCerts {
		t.Run(region, func(t *testing.T) {
			// Parse PEM
			block, _ := pem.Decode([]byte(certPEM))
			require.NotNil(t, block, "failed to decode PEM for region %s", region)

			// Parse certificate
			cert, err := x509.ParseCertificate(block.Bytes)
			require.NoError(t, err, "failed to parse certificate for region %s", region)

			// Verify it's RSA
			require.Equal(t, x509.RSA, cert.PublicKeyAlgorithm,
				"region %s must use RSA certificate", region)

			// Verify not expired
			now := time.Now()
			require.False(t, now.Before(cert.NotBefore),
				"region %s: certificate not yet valid (valid from %s)", region, cert.NotBefore)
			require.False(t, now.After(cert.NotAfter),
				"region %s: certificate expired on %s", region, cert.NotAfter)

			t.Logf("Region %s: valid RSA certificate, expires %s", region, cert.NotAfter.Format("2006-01-02"))
		})
	}
}

// fetchAWSRSACertificates downloads the AWS documentation page and extracts
// all RSA certificates (not RSA-2048) for each region.
func fetchAWSRSACertificates() (map[string]string, error) {
	resp, err := http.Get(awsDocsURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch AWS docs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AWS docs returned status %d", resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML: %w", err)
	}

	certs := make(map[string]string)

	// Each region is in an <awsui-expandable-section> with a header attribute
	doc.Find("awsui-expandable-section").Each(func(i int, section *goquery.Selection) {
		header := section.AttrOr("header", "")
		region := extractRegionFromHeader(header)
		if region == "" {
			return
		}

		// Find the definition list containing the certificates
		dl := section.Find("dl")
		if dl.Length() == 0 {
			return
		}

		// Look for <dt>RSA</dt> (not RSA-2048)
		dl.Find("dt").Each(func(j int, dt *goquery.Selection) {
			term := strings.TrimSpace(dt.Text())
			if term != "RSA" {
				return
			}

			// Get the next <dd> element which contains the certificate
			dd := dt.NextFiltered("dd")
			if dd.Length() == 0 {
				return
			}

			// Extract certificate from the text
			certPEM, err := extractCertificateFromText(dd.Text())
			if err == nil {
				certs[region] = certPEM
			}
		})
	})

	return certs, nil
}

// extractRegionFromHeader extracts the region code from a header like
// "US East (N. Virginia) — us-east-1"
func extractRegionFromHeader(header string) string {
	// Split on em dash (—)
	parts := strings.Split(header, "—")
	if len(parts) != 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// extractCertificateFromText extracts a PEM certificate from text,
// cleaning up whitespace and HTML artifacts.
func extractCertificateFromText(text string) (string, error) {
	const begin = "-----BEGIN CERTIFICATE-----"
	const end = "-----END CERTIFICATE-----"

	start := strings.Index(text, begin)
	finish := strings.Index(text, end)

	if start == -1 || finish == -1 {
		return "", fmt.Errorf("certificate delimiters not found")
	}

	// Extract the certificate block
	block := text[start : finish+len(end)]
	block = strings.TrimSpace(block)

	// Clean up: remove empty lines and trim each line
	lines := strings.Split(block, "\n")
	cleaned := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			cleaned = append(cleaned, line)
		}
	}

	return strings.Join(cleaned, "\n"), nil
}

// normalizeCertPEM removes all whitespace from a PEM certificate for comparison
func normalizeCertPEM(certPEM string) string {
	return strings.Join(strings.Fields(certPEM), "")
}

// parseCertificate parses a PEM-encoded certificate and returns the x509.Certificate
func parseCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}
