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

// Package testdata contains test data for the secretscan package.
package testdata

// TestSecrets contains examples for testing the secret scanning functionality.
// These are NOT real secrets - they are placeholder patterns for testing detection.
var TestSecrets = struct {
	GitHubToken  string // GitHub personal access token
	AWSKey       string // AWS access key
	GoogleAPIKey string // Google API key
	SlackToken   string // Slack API token
	StripeKey    string // Stripe API key
	SendGridKey  string // SendGrid API key
	JWTToken     string // JWT token example
	PrivateKey   string // Private key example
	AuthURL      string // URL with basic auth
	Base64Token  string // Base64 encoded token
	DoubleB64    string // Double base64 encoded token
	TripleB64    string // Triple base64 encoded token
	URLEncoded   string // URL encoded secret
	MixedEncoded string // Mixed encoding (url+base64+hex)
}{
	GitHubToken:  "ghp_012345678901234567890123456789",
	AWSKey:       "AKIAIOSFODNN7EXAMPLE",
	GoogleAPIKey: "AIzaSyDdoASSAD90YgOUNWXQLTIZTZ0oh13zU10",
	SlackToken:   "xoxp-TEST1234-TEST1234-TEST1234-1234abcdeftest",
	StripeKey:    "sk_test_1234567890abcdefghijklmnopqrstuvw",
	SendGridKey:  "SG.1234567890abcdefghijklmnopqrstuvwx.1234567890abcdefghijklmnopqrstuvwxyz1234",
	JWTToken:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
	PrivateKey:   "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB\n-----END RSA PRIVATE KEY-----",
	AuthURL:      "https://username:password@example.com",
	Base64Token:  "Z2hwXzAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTA=", // Base64 of GitHub token
	DoubleB64:    "WjJod1hqQXhNak0wTlRZM09Ea3dNVEl6TkRVMk56ZzVNREV5TXpRMU5qYzRPVEE9", // Double base64 of GitHub token
	TripleB64:    "V2pkb2RGaEFNVEl6TkRVMk56ZzVNREV5TXpRMU5qYzRPVEF4TWpNME5UWTNPRGt3UFE9PQ==", // Triple base64
	URLEncoded:   "ghp%5F012345678901234567890123456789", // URL encoded GitHub token
	MixedEncoded: "Z2hwJTVGMDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MA==", // URL in base64
}