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

package aws_iid

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/stretchr/testify/require"
)

const iid = `{
  "accountId" : "123456789012",
  "architecture" : "x86_64",
  "availabilityZone" : "eu-west-2a",
  "billingProducts" : null,
  "devpayProductCodes" : null,
  "marketplaceProductCodes" : null,
  "imageId" : "ami-0336cdd409ab5eec4",
  "instanceId" : "i-09fb86d76201dce1c",
  "instanceType" : "t3.micro",
  "kernelId" : null,
  "pendingTime" : "2025-10-05T23:09:26Z",
  "privateIp" : "172.31.17.243",
  "ramdiskId" : null,
  "region" : "eu-west-2",
  "version" : "2017-09-30"
}`

const sig = `MuyIdlA+nFQ87y/qQQoCNZe8cVZFRGF53j4oAFl5EX8PKKgG1hFGn2S43z/TvwZOR+PH+GchG9PMUQNR+6UYvyJ0g1fh/PnQL2dLibAY91GuWa4G2nV8Yj9qrKqTbbibWAtdaeBOkyP1biQuC2SveJaWFjuRYSDAhtDpT4ge20Q=`

const badsig = `YmFkIHNpZ25hdHVyZQo=`

const testCert = `-----BEGIN CERTIFICATE-----
MIICeDCCAeGgAwIBAgIUEEbUY4pG0unhrw3egknEmgbbHnMwDQYJKoZIhvcNAQEL
BQAwZzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1TYW4gRnJh
bmNpc2NvMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxEDAOBgNV
BAMMB1dpdG5lc3MwHhcNMjUxMDA3MTgxNjMxWhcNMzUxMDA1MTgxNjMxWjBnMQsw
CQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28x
ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEQMA4GA1UEAwwHV2l0
bmVzczCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA5dGx5i6LRVCBuW+dbyR6
10+U4PMoHT2C8shlrtgaOBM5VJXNImnecJl50fTI+6aTIqpq2x1r0iQJxuAEWrRp
ycVlXdexcqWdyhU4BS2wJBrT9EkTtWyDiDX35JGHVFhBDzu8afuyB7cX9huq6EB7
8zWsDBq64IU1z7Fr931j8G8CAwEAAaMhMB8wHQYDVR0OBBYEFPmqy7XhH47XNPuL
+VlCgDWYbA9fMA0GCSqGSIb3DQEBCwUAA4GBADbzOv2GtA2frJ0c9m6kd2hVGnB7
+/UuPy/XOZNiMoZpC1fuGnjmeVCg4r2wtdjG01ssS7s8R/3Id/Oc/kTTNnhmAna0
T2KEmoohLmK2mQz8NAu0xaOrKMDX6gyJGacw7ig6qjDNsUz3Sjl4NBkEe9cc2wXc
kHPb0HdH2xJYhM7T
-----END CERTIFICATE-----`

type testresp struct {
	path string
	resp string
}

func GetTestResponses() []testresp {
	return []testresp{
		{"/latest/dynamic/instance-identity/document", iid},
		{"/latest/dynamic/instance-identity/signature", sig},
		{"/latest/api/token", "testtoken"},
	}
}

func initTestServer(t *testing.T, testresponses []testresp) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, resp := range testresponses {
			if r.URL.Path == resp.path {
				_, err := w.Write([]byte(resp.resp))
				require.NoError(t, err)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
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
	var tests = []struct {
		name    string
		resp    []testresp
		errNil  bool
		errText string
	}{
		{
			"Valid IID",
			[]testresp{
				{"/latest/dynamic/instance-identity/document", iid},
				{"/latest/dynamic/instance-identity/signature", sig},
				{"/latest/api/token", "testtoken"},
			},
			true,
			"",
		},
		{
			"No Signature",
			[]testresp{
				{"/latest/dynamic/instance-identity/document", iid},
				{"/latest/dynamic/instance-identity/signature", ""},
				{"/latest/api/token", "testtoken"},
			},
			false,
			"instance identity document or signature is empty",
		},
		{
			"Verification Fail",
			[]testresp{
				{"/latest/dynamic/instance-identity/document", iid},
				{"/latest/dynamic/instance-identity/signature", badsig},
				{"/latest/api/token", "testtoken"},
			},
			false,
			"crypto/rsa: verification error",
		},
		{
			"Bad Signature",
			[]testresp{
				{"/latest/dynamic/instance-identity/document", iid},
				{"/latest/dynamic/instance-identity/signature", "12345"},
				{"/latest/api/token", "testtoken"},
			},
			false,
			"failed to decode signature:",
		},
	}

	for _, test := range tests {
		a := New(WithAWSRegionCert(testCert))

		t.Run(test.name, func(t *testing.T) {
			server := initTestServer(t, test.resp)
			defer server.Close()

			endpoint := server.URL + "/latest"
			cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithEC2IMDSEndpoint(endpoint))
			if err != nil {
				t.Fatalf("failed to load AWS config: %v", err)
			}
			a.cfg = cfg

			ctx, err := attestation.NewContext("test", []attestation.Attestor{a})
			require.NoError(t, err)
			err = a.Attest(ctx)
			if test.errNil {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.Contains(t, err.Error(), test.errText)
			}
		})
	}
}

func TestAttestor_getIID(t *testing.T) {
	server := initTestServer(t, GetTestResponses())
	defer server.Close()

	endpoint := server.URL + "/latest"
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithEC2IMDSEndpoint(endpoint))
	if err != nil {
		t.Fatalf("failed to load AWS config: %v", err)
	}

	a := &Attestor{
		cfg: cfg,
	}

	err = a.getIID()
	require.NoError(t, err)

}

func TestAttestor_Subjects(t *testing.T) {
	server := initTestServer(t, GetTestResponses())
	defer server.Close()

	a := New(WithAWSRegionCert(testCert))
	endpoint := server.URL + "/latest"
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithEC2IMDSEndpoint(endpoint))
	if err != nil {
		t.Fatalf("failed to load AWS config: %v", err)
	}
	a.cfg = cfg

	ctx, err := attestation.NewContext("test", []attestation.Attestor{a})
	require.NoError(t, err)
	err = a.Attest(ctx)
	require.NoError(t, err)

	res := a.Subjects()

	if len(res) != 4 {
		t.Errorf("Expected 8 subjects, got %d", len(res))
	}

	imageid := sha256.Sum256([]byte("ami-0336cdd409ab5eec4"))
	digest := res["imageid:ami-0336cdd409ab5eec4"]
	h := digest[cryptoutil.DigestValue{Hash: crypto.SHA256}]
	h2 := hex.EncodeToString(imageid[:])
	if h != h2 {
		t.Errorf("Expected %s, got %s", h, h2)
	}

}

func Test_getAWSPublicKey(t *testing.T) {
	key, err := getAWSCAPublicKey(testCert)
	require.NoError(t, err)
	if key == nil {
		t.Error("Expected key to not be nil")
	}
}
