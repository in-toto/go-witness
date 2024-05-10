// Copyright 2023 The Witness Contributors
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

package policy

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/policy"
	"github.com/in-toto/go-witness/timestamp"
)

type VerifyPolicySignatureOptions struct {
	policyVerifiers            []cryptoutil.Verifier
	policyTimestampAuthorities []timestamp.TimestampVerifier
	policyCARoots              []*x509.Certificate
	policyCAIntermediates      []*x509.Certificate
	policyCommonName           string
	policyDNSNames             []string
	policyEmails               []string
	policyOrganizations        []string
	policyURIs                 []string
}

type Option func(*VerifyPolicySignatureOptions)

func VerifyWithPolicyVerifiers(policyVerifiers []cryptoutil.Verifier) Option {
	return func(vo *VerifyPolicySignatureOptions) {
		vo.policyVerifiers = append(vo.policyVerifiers, policyVerifiers...)
	}
}

func VerifyWithPolicyTimestampAuthorities(authorities []timestamp.TimestampVerifier) Option {
	return func(vo *VerifyPolicySignatureOptions) {
		vo.policyTimestampAuthorities = authorities
	}
}

func VerifyWithPolicyCARoots(roots []*x509.Certificate) Option {
	return func(vo *VerifyPolicySignatureOptions) {
		vo.policyCARoots = roots
	}
}

func VerifyWithPolicyCAIntermediates(intermediates []*x509.Certificate) Option {
	return func(vo *VerifyPolicySignatureOptions) {
		vo.policyCAIntermediates = intermediates
	}
}

func NewVerifyPolicySignatureOptions(opts ...Option) *VerifyPolicySignatureOptions {
	vo := &VerifyPolicySignatureOptions{
		policyCommonName:    "*",
		policyDNSNames:      []string{"*"},
		policyOrganizations: []string{"*"},
		policyURIs:          []string{"*"},
		policyEmails:        []string{"*"},
	}

	for _, opt := range opts {
		opt(vo)
	}

	return vo
}

func VerifyWithPolicyCertConstraints(commonName string, dnsNames []string, emails []string, organizations []string, uris []string) Option {
	return func(vo *VerifyPolicySignatureOptions) {
		vo.policyCommonName = commonName
		vo.policyDNSNames = dnsNames
		vo.policyEmails = emails
		vo.policyOrganizations = organizations
		vo.policyURIs = uris
	}
}

func VerifyPolicySignature(ctx context.Context, envelope dsse.Envelope, vo *VerifyPolicySignatureOptions) error {
	passedPolicyVerifiers, err := envelope.Verify(dsse.VerifyWithVerifiers(vo.policyVerifiers...), dsse.VerifyWithTimestampVerifiers(vo.policyTimestampAuthorities...), dsse.VerifyWithRoots(vo.policyCARoots...), dsse.VerifyWithIntermediates(vo.policyCAIntermediates...))
	if err != nil {
		return fmt.Errorf("could not verify policy: %w", err)
	}

	var passed bool
	for _, verifier := range passedPolicyVerifiers {
		kid, err := verifier.Verifier.KeyID()
		if err != nil {
			return fmt.Errorf("could not get verifier key id: %w", err)
		}

		var f policy.Functionary
		trustBundle := make(map[string]policy.TrustBundle)
		if _, ok := verifier.Verifier.(*cryptoutil.X509Verifier); ok {
			rootIDs := make([]string, 0)
			for _, root := range vo.policyCARoots {
				id := base64.StdEncoding.EncodeToString(root.Raw)
				rootIDs = append(rootIDs, id)
				trustBundle[id] = policy.TrustBundle{
					Root: root,
				}
			}

			f = policy.Functionary{
				Type: "root",
				CertConstraint: policy.CertConstraint{
					Roots:         rootIDs,
					CommonName:    vo.policyCommonName,
					URIs:          vo.policyURIs,
					Emails:        vo.policyEmails,
					Organizations: vo.policyOrganizations,
					DNSNames:      vo.policyDNSNames,
				},
			}

		} else {
			f = policy.Functionary{
				Type:        "key",
				PublicKeyID: kid,
			}
		}

		err = f.Validate(verifier.Verifier, trustBundle)
		if err != nil {
			log.Debugf("Policy Verifier %s failed failed to match supplied constraints: %w, continuing...", kid, err)
			continue
		}
		passed = true
	}

	if !passed {
		return fmt.Errorf("no policy verifiers passed verification")
	} else {
		return nil
	}
}
