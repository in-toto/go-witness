// Copyright 2022 The Witness Contributors
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

package timestamp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	tstamp "github.com/digitorus/timestamp"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/internal/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	tsaUrl = "https://timestamp.sigstore.dev/api/v1/timestamp"
	tsaCA  = `-----BEGIN CERTIFICATE-----
MIICEDCCAZagAwIBAgIUOhNULwyQYe68wUMvy4qOiyojiwwwCgYIKoZIzj0EAwMw
OTEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MSAwHgYDVQQDExdzaWdzdG9yZS10c2Et
c2VsZnNpZ25lZDAeFw0yNTA0MDgwNjU5NDNaFw0zNTA0MDYwNjU5NDNaMC4xFTAT
BgNVBAoTDHNpZ3N0b3JlLmRldjEVMBMGA1UEAxMMc2lnc3RvcmUtdHNhMHYwEAYH
KoZIzj0CAQYFK4EEACIDYgAE4ra2Z8hKNig2T9kFjCAToGG30jky+WQv3BzL+mKv
h1SKNR/UwuwsfNCg4sryoYAd8E6isovVA3M4aoNdm9QDi50Z8nTEyvqgfDPtTIwX
ItfiW/AFf1V7uwkbkAoj0xxco2owaDAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYE
FIn9eUOHz9BlRsMCRscsc1t9tOsDMB8GA1UdIwQYMBaAFJjsAe9/u1H/1JUeb4qI
mFMHic6/MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMAoGCCqGSM49BAMDA2gAMGUC
MDtpsV/6KaO0qyF/UMsX2aSUXKQFdoGTptQGc0ftq1csulHPGG6dsmyMNd3JB+G3
EQIxAOajvBcjpJmKb4Nv+2Taoj8Uc5+b6ih6FXCCKraSqupe07zqswMcXJTe1cEx
vHvvlw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIB9zCCAXygAwIBAgIUV7f0GLDOoEzIh8LXSW80OJiUp14wCgYIKoZIzj0EAwMw
OTEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MSAwHgYDVQQDExdzaWdzdG9yZS10c2Et
c2VsZnNpZ25lZDAeFw0yNTA0MDgwNjU5NDNaFw0zNTA0MDYwNjU5NDNaMDkxFTAT
BgNVBAoTDHNpZ3N0b3JlLmRldjEgMB4GA1UEAxMXc2lnc3RvcmUtdHNhLXNlbGZz
aWduZWQwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQUQNtfRT/ou3YATa6wB/kKTe70
cfJwyRIBovMnt8RcJph/COE82uyS6FmppLLL1VBPGcPfpQPYJNXzWwi8icwhKQ6W
/Qe2h3oebBb2FHpwNJDqo+TMaC/tdfkv/ElJB72jRTBDMA4GA1UdDwEB/wQEAwIB
BjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSY7AHvf7tR/9SVHm+KiJhT
B4nOvzAKBggqhkjOPQQDAwNpADBmAjEAwGEGrfGZR1cen1R8/DTVMI943LssZmJR
tDp/i7SfGHmGRP6gRbuj9vOK3b67Z0QQAjEAuT2H673LQEaHTcyQSZrkp4mX7Wwk
mF+sVbkYY5mXN+RMH13KUEHHOqASaemYWK/E
-----END CERTIFICATE-----`
	otherCA = `-----BEGIN CERTIFICATE-----
MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzET
MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0
MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBw
bGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx
FjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg+
+FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1
XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9w
tj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IW
q6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKM
aLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8E
BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3
R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAE
ggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93
d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNl
IG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0
YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBj
b25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZp
Y2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBc
NplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQP
y3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7
R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr1KIkIxH3oayPc4Fg
xhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltkwGMzd/c6ByxW69oP
IQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPIS4AX
UKqK1drk/NAJBzewdXUh
-----END CERTIFICATE-----`
)

func TestTSP(t *testing.T) {
	ts := NewTimestamper(TimestampWithUrl(tsaUrl))
	payload := []byte("some data to timestamp")
	resp, err := ts.Timestamp(context.Background(), bytes.NewReader(payload))
	require.NoError(t, err)
	cert, err := cryptoutil.TryParseCertificate([]byte(tsaCA))
	require.NoError(t, err)
	otherCert, err := cryptoutil.TryParseCertificate([]byte(otherCA))
	require.NoError(t, err)
	v := NewVerifier(VerifyWithCerts([]*x509.Certificate{cert}))

	t.Run("pass", func(t *testing.T) {
		signedTime, err := v.Verify(context.Background(), bytes.NewReader(resp), bytes.NewReader(payload))
		assert.NoError(t, err)
		assert.NotZero(t, signedTime)
	})

	t.Run("incorrect payload", func(t *testing.T) {
		signedTime, err := v.Verify(context.Background(), bytes.NewReader(resp), bytes.NewReader([]byte("this is not what was timestamped")))
		assert.Error(t, err)
		assert.Zero(t, signedTime)
	})

	t.Run("incorrect cert", func(t *testing.T) {
		v = NewVerifier(VerifyWithCerts([]*x509.Certificate{otherCert}))
		signedTime, err := v.Verify(context.Background(), bytes.NewReader(resp), bytes.NewReader(payload))
		assert.Error(t, err)
		assert.Zero(t, signedTime)
	})
}

var (
	oidEKUTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidEKUServerAuth   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
)

// makeEKUExtension builds an extended-key-usage extension (OID 2.5.29.37) with the given EKU OIDs
// and criticality. It is needed because x509.CreateCertificate always marks the template
// ExtKeyUsage field non-critical, while RFC 3161 requires the TSA EKU extension to be critical.
func makeEKUExtension(t *testing.T, critical bool, ekus ...asn1.ObjectIdentifier) pkix.Extension {
	t.Helper()
	val, err := asn1.Marshal(ekus)
	require.NoError(t, err)
	return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: critical, Value: val}
}

// issueAndVerify signs a timestamp with a leaf built from leafTmpl under root, then runs the
// verifier with root as the sole trust anchor and returns the verifier's result.
func issueAndVerify(t *testing.T, rootCert *x509.Certificate, rootKey interface{}, leafTmpl *x509.Certificate) (time.Time, error) {
	t.Helper()
	leafPriv, leafPub, err := test.CreateRsaKey()
	require.NoError(t, err)
	leafCert, err := test.CreateCert(rootKey, leafPub, leafTmpl, rootCert)
	require.NoError(t, err)

	signedData := []byte("the signature bytes being timestamped")
	digest := sha256.Sum256(signedData)
	ts := tstamp.Timestamp{
		HashAlgorithm:     crypto.SHA256,
		HashedMessage:     digest[:],
		Time:              time.Now().UTC(),
		Nonce:             big.NewInt(0).SetBytes([]byte{0x1, 0x2, 0x3}),
		Policy:            []int{2, 4, 5, 6},
		Accuracy:          time.Second,
		AddTSACertificate: true,
	}
	respBytes, err := ts.CreateResponseWithOpts(leafCert, leafPriv, crypto.SHA256)
	require.NoError(t, err)
	parsed, err := tstamp.ParseResponse(respBytes)
	require.NoError(t, err)

	return NewVerifier(VerifyWithCerts([]*x509.Certificate{rootCert})).
		Verify(context.Background(), bytes.NewReader(parsed.RawToken), bytes.NewReader(signedData))
}

func baseLeafTemplate(cn string) *x509.Certificate {
	return &x509.Certificate{
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
}

// A TSA signing certificate that lacks the id-kp-timeStamping EKU (here it carries ServerAuth) must
// be rejected as a timestamp signer.
func TestVerifyRejectsCertWithoutTimestampingEKU(t *testing.T) {
	rootCert, rootKey, err := test.CreateRoot()
	require.NoError(t, err)

	leafPriv, leafPub, err := test.CreateRsaKey()
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "not-a-timestamper.example"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	leafCert, err := test.CreateCert(rootKey, leafPub, leafTmpl, rootCert)
	require.NoError(t, err)

	signedData := []byte("the signature bytes being timestamped")
	digest := sha256.Sum256(signedData)
	ts := tstamp.Timestamp{
		HashAlgorithm:     crypto.SHA256,
		HashedMessage:     digest[:],
		Time:              time.Now().UTC(),
		Nonce:             big.NewInt(0).SetBytes([]byte{0x1, 0x2, 0x3}),
		Policy:            []int{2, 4, 5, 6},
		Accuracy:          time.Second,
		AddTSACertificate: true,
	}
	respBytes, err := ts.CreateResponseWithOpts(leafCert, leafPriv, crypto.SHA256)
	require.NoError(t, err)
	parsed, err := tstamp.ParseResponse(respBytes)
	require.NoError(t, err)

	_, err = NewVerifier(VerifyWithCerts([]*x509.Certificate{rootCert})).
		Verify(context.Background(), bytes.NewReader(parsed.RawToken), bytes.NewReader(signedData))
	require.Error(t, err, "timestamp accepted from a certificate without the id-kp-timeStamping EKU")
}

// A leaf carrying a sole, critical timestamping EKU is a valid TSA signer and must be accepted.
func TestVerifyAcceptsSoleCriticalTimestampingEKU(t *testing.T) {
	rootCert, rootKey, err := test.CreateRoot()
	require.NoError(t, err)
	leafTmpl := baseLeafTemplate("valid-tsa.example")
	leafTmpl.ExtraExtensions = []pkix.Extension{makeEKUExtension(t, true, oidEKUTimeStamping)}

	tt, err := issueAndVerify(t, rootCert, rootKey, leafTmpl)
	require.NoError(t, err, "a leaf with a sole, critical timestamping EKU must be accepted")
	require.False(t, tt.IsZero())
}

// A timestamping EKU that is not marked critical must be rejected, as RFC 3161 requires the EKU
// extension to be critical.
func TestVerifyRejectsNonCriticalTimestampingEKU(t *testing.T) {
	rootCert, rootKey, err := test.CreateRoot()
	require.NoError(t, err)
	leafTmpl := baseLeafTemplate("noncritical-tsa.example")
	leafTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping} // marked non-critical by Go

	_, err = issueAndVerify(t, rootCert, rootKey, leafTmpl)
	require.ErrorContains(t, err, "must be marked critical")
}

// A certificate that carries timestamping alongside another EKU must be rejected: RFC 3161 requires
// timestamping to be the sole extended key usage.
func TestVerifyRejectsMultipleEKUs(t *testing.T) {
	rootCert, rootKey, err := test.CreateRoot()
	require.NoError(t, err)
	leafTmpl := baseLeafTemplate("multi-eku-tsa.example")
	leafTmpl.ExtraExtensions = []pkix.Extension{makeEKUExtension(t, true, oidEKUTimeStamping, oidEKUServerAuth)}

	_, err = issueAndVerify(t, rootCert, rootKey, leafTmpl)
	require.ErrorContains(t, err, "only EKU")
}
