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
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/registry"
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
	// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-iid.html
	// There is a different public cert for every AWS region
	// You can find the one you need for verification here:
	// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/regions-certs.html
)

var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	},
		registry.StringConfigOption(
			"region-cert",
			"A public x509 certificate used to verify the AWS instance identity document signature.",
			"",
			func(a attestation.Attestor, val string) (attestation.Attestor, error) {
				attestor, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithAWSRegionCert(val)(attestor)
				return attestor, nil
			},
		))
}

type Option func(*Attestor)

func WithAWSRegionCert(awsCert string) Option {
	return func(a *Attestor) {
		a.awsCert = awsCert
	}
}

type Attestor struct {
	imds.InstanceIdentityDocument
	hashes    []cryptoutil.DigestValue
	cfg       aws.Config
	awsCert   string
	RawIID    string `json:"rawiid"`
	RawSig    string `json:"rawsig"`
	PublicKey string `json:"publickey"`
}

func New(opts ...Option) *Attestor {
	attestor := &Attestor{}
	for _, opt := range opts {
		opt(attestor)
	}

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Errorf("failed to load AWS config: %v", err)
		return nil
	}
	attestor.cfg = cfg

	return attestor
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
	client := imds.NewFromConfig(a.cfg)

	iid, err := client.GetDynamicData(context.TODO(), &imds.GetDynamicDataInput{Path: docPath})
	if err != nil {
		return fmt.Errorf("failed to get instance identity document: %w", err)
	}

	content, err := io.ReadAll(iid.Content)
	if err != nil {
		return fmt.Errorf("failed to read instance identity document: %w", err)
	}
	a.RawIID = string(content)

	sig, err := client.GetDynamicData(context.TODO(), &imds.GetDynamicDataInput{Path: sigPath})
	if err != nil {
		return fmt.Errorf("failed to get instance identity signature: %w", err)
	}

	content, err = io.ReadAll(sig.Content)
	if err != nil {
		return fmt.Errorf("failed to read instance identity document: %w", err)
	}
	a.RawSig = string(content)

	err = json.Unmarshal([]byte(a.RawIID), &a.InstanceIdentityDocument)
	if err != nil {
		return fmt.Errorf("failed to unmarshal instance identity document: %w", err)
	}

	return nil
}

func (a *Attestor) Verify() error {
	if len(a.RawIID) == 0 || len(a.RawSig) == 0 {
		return fmt.Errorf("instance identity document or signature is empty")
	}

	docHash := sha256.Sum256([]byte(a.RawIID))
	sigBytes, err := base64.StdEncoding.DecodeString(a.RawSig)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	pubKey, err := getAWSCAPublicKey(a.cfg.Region, a.awsCert)
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

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, docHash[:], sigBytes)
	if err != nil {
		log.Debugf("(attestation/aws-iid) failed to verify signature: %w", err)
		return err
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

func getAWSCAPublicKey(awsRegion, awsCert string) (*rsa.PublicKey, error) {
	if awsCert == "" {
		var err error
		awsCert, err = getRegionCert(awsRegion)
		if err != nil {
			return nil, err
		}
	}

	block, rest := pem.Decode([]byte(awsCert))
	if len(rest) > 0 {
		return nil, fmt.Errorf("failed to decode PEM block containing the public key")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
		return nil, fmt.Errorf("%s: certificate is not valid at the current time", awsRegion)
	}

	if cert.PublicKeyAlgorithm != x509.RSA {
		return nil, fmt.Errorf("%s: unexpected public key algorithm: %v", awsRegion, cert.PublicKeyAlgorithm)
	}

	return cert.PublicKey.(*rsa.PublicKey), nil
}
