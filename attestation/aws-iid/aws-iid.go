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

package aws_iid

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "aws"
	Type    = "https://witness.dev/attestations/aws/v0.1"
	RunType = attestation.PreMaterialRunType
)

// These will be configurable in the future
const (
	docPath = "instance-identity/document"
	sigPath = "instance-identity/signature"
	// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-signature.html
	// The following AWS public certificate is for all AWS Regions, except Hong Kong, Bahrain, China, and GovCloud.
	awsCACertPEM = `-----BEGIN CERTIFICATE-----
MIIDIjCCAougAwIBAgIJAKnL4UEDMN/FMA0GCSqGSIb3DQEBBQUAMGoxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdTZWF0dGxlMRgw
FgYDVQQKEw9BbWF6b24uY29tIEluYy4xGjAYBgNVBAMTEWVjMi5hbWF6b25hd3Mu
Y29tMB4XDTE0MDYwNTE0MjgwMloXDTI0MDYwNTE0MjgwMlowajELMAkGA1UEBhMC
VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1NlYXR0bGUxGDAWBgNV
BAoTD0FtYXpvbi5jb20gSW5jLjEaMBgGA1UEAxMRZWMyLmFtYXpvbmF3cy5jb20w
gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAIe9GN//SRK2knbjySG0ho3yqQM3
e2TDhWO8D2e8+XZqck754gFSo99AbT2RmXClambI7xsYHZFapbELC4H91ycihvrD
jbST1ZjkLQgga0NE1q43eS68ZeTDccScXQSNivSlzJZS8HJZjgqzBlXjZftjtdJL
XeE4hwvo0sD4f3j9AgMBAAGjgc8wgcwwHQYDVR0OBBYEFCXWzAgVyrbwnFncFFIs
77VBdlE4MIGcBgNVHSMEgZQwgZGAFCXWzAgVyrbwnFncFFIs77VBdlE4oW6kbDBq
MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHU2Vh
dHRsZTEYMBYGA1UEChMPQW1hem9uLmNvbSBJbmMuMRowGAYDVQQDExFlYzIuYW1h
em9uYXdzLmNvbYIJAKnL4UEDMN/FMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEF
BQADgYEAFYcz1OgEhQBXIwIdsgCOS8vEtiJYF+j9uO6jz7VOmJqO+pRlAbRlvY8T
C1haGgSI/A1uZUKs/Zfnph0oEI0/hu1IIJ/SKBDtN5lvmZ/IzbOPIJWirlsllQIQ
7zvWbGd9c9+Rm3p04oTvhup99la7kZqevJK0QRdD/6NpCKsqP/0=
-----END CERTIFICATE-----`
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type Attestor struct {
	ec2metadata.EC2InstanceIdentityDocument
	hashes    []cryptoutil.DigestValue
	session   session.Session
	conf      *aws.Config
	RawIID    string `json:"rawiid"`
	RawSig    string `json:"rawsig"`
	PublicKey string `json:"publickey"`
}

func New() *Attestor {
	sess, err := session.NewSession()
	if err != nil {
		return nil
	}

	conf := &aws.Config{}
	return &Attestor{
		session: *sess,
		conf:    conf,
	}
}

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) Type() string {
	return Type
}

func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&a)
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	a.hashes = ctx.Hashes()

	err := a.getIID()
	if err != nil {
		return err
	}

	err = a.Verify()
	if err != nil {
		return err
	}

	return nil
}

func (a *Attestor) getIID() error {
	svc := ec2metadata.New(&a.session, a.conf)
	iid, err := svc.GetDynamicData(docPath)
	if err != nil {
		return fmt.Errorf("failed to get instance identity document: %w", err)
	}

	sig, err := svc.GetDynamicData(sigPath)
	if err != nil {
		return fmt.Errorf("failed to get signature: %w", err)
	}

	a.RawIID = iid
	a.RawSig = sig

	err = json.Unmarshal([]byte(a.RawIID), &a.EC2InstanceIdentityDocument)
	if err != nil {
		return fmt.Errorf("failed to unmarshal iid: %w", err)
	}

	return nil
}

func (a *Attestor) Verify() error {
	if len(a.RawIID) == 0 || len(a.RawSig) == 0 {
		return nil
	}

	docHash := sha256.Sum256([]byte(a.RawIID))
	sigBytes, err := base64.StdEncoding.DecodeString(a.RawSig)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	pubKey, err := getAWSCAPublicKey()
	if err != nil {
		return fmt.Errorf("failed to get AWS public key: %w", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	pem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	a.PublicKey = string(pem)

	if err != nil {
		return fmt.Errorf("failed to encode public key: %w", err)
	}

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, docHash[:], sigBytes)
	if err != nil {
		log.Debugf("(attestation/aws-iid) failed to verify signature: %w", err)
		return nil
	}

	return nil
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	subjects := make(map[string]cryptoutil.DigestSet)
	if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(a.InstanceID), hashes); err == nil {
		subjects[fmt.Sprintf("instanceid:%s", a.InstanceID)] = ds
	} else {
		log.Debugf("(attestation/aws) failed to record aws instanceid subject: %w", err)
	}

	if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(a.AccountID), hashes); err == nil {
		subjects[fmt.Sprintf("accountid:%s", a.AccountID)] = ds
	} else {
		log.Debugf("(attestation/aws) failed to record aws accountid subject: %w", err)
	}

	if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(a.ImageID), hashes); err == nil {
		subjects[fmt.Sprintf("imageid:%s", a.ImageID)] = ds
	} else {
		log.Debugf("(attestation/aws) failed to record aws imageid subject: %w", err)
	}

	if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(a.PrivateIP), hashes); err == nil {
		subjects[fmt.Sprintf("privateip:%s", a.PrivateIP)] = ds
	} else {
		log.Debugf("(attestation/aws) failed to record aws privateip subject: %w", err)
	}

	return subjects
}

func getAWSCAPublicKey() (*rsa.PublicKey, error) {
	block, rest := pem.Decode([]byte(awsCACertPEM))
	if len(rest) > 0 {
		return nil, fmt.Errorf("failed to decode PEM block containing the public key")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert.PublicKey.(*rsa.PublicKey), nil
}
