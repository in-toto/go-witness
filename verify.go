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

package witness

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/edwarnicke/gitoid"
	"github.com/testifysec/go-witness/cryptoutil"
	"github.com/testifysec/go-witness/dsse"
	"github.com/testifysec/go-witness/log"
	"github.com/testifysec/go-witness/policy"
	"github.com/testifysec/go-witness/source"
	"github.com/testifysec/go-witness/timestamp"
)

func VerifySignature(r io.Reader, verifiers ...cryptoutil.Verifier) (dsse.Envelope, error) {
	decoder := json.NewDecoder(r)
	envelope := dsse.Envelope{}
	if err := decoder.Decode(&envelope); err != nil {
		return envelope, fmt.Errorf("failed to parse dsse envelope: %v", err)
	}

	_, err := envelope.Verify(dsse.VerifyWithVerifiers(verifiers...))
	return envelope, err
}

type verifyOptions struct {
	policyEnvelope   dsse.Envelope
	policyVerifiers  []cryptoutil.Verifier
	collectionSource source.Sourcer
	subjectDigests   []string
	decisionLogURL   string
}

type VerifyOption func(*verifyOptions)

func VerifyWithSubjectDigests(subjectDigests []cryptoutil.DigestSet) VerifyOption {
	return func(vo *verifyOptions) {
		for _, set := range subjectDigests {
			for _, digest := range set {
				vo.subjectDigests = append(vo.subjectDigests, digest)
			}
		}
	}
}

func VerifyWithCollectionSource(source source.Sourcer) VerifyOption {
	return func(vo *verifyOptions) {
		vo.collectionSource = source
	}
}

func VerifyWithDecisionLogProvider(decisionLogURL string) VerifyOption {
	return func(vo *verifyOptions) {
		vo.decisionLogURL = decisionLogURL
	}
}

// Verify verifies a set of attestations against a provided policy. The set of attestations that satisfy the policy will be returned
// if verifiation is successful.
func Verify(ctx context.Context, policyEnvelope dsse.Envelope, policyVerifiers []cryptoutil.Verifier, opts ...VerifyOption) (map[string][]source.VerifiedCollection, error) {
	vo := verifyOptions{
		policyEnvelope:  policyEnvelope,
		policyVerifiers: policyVerifiers,
	}

	for _, opt := range opts {
		opt(&vo)
	}

	if _, err := vo.policyEnvelope.Verify(dsse.VerifyWithVerifiers(vo.policyVerifiers...)); err != nil {
		return nil, fmt.Errorf("could not verify policy: %w", err)
	}

	pol := policy.Policy{}
	if err := json.Unmarshal(vo.policyEnvelope.Payload, &pol); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy from envelope: %w", err)
	}

	pubKeysById, verifyErr := pol.PublicKeyVerifiers()
	if verifyErr != nil {
		return nil, fmt.Errorf("failed to get pulic keys from policy: %w", verifyErr)
	}

	pubkeys := make([]cryptoutil.Verifier, 0)
	for _, pubkey := range pubKeysById {
		pubkeys = append(pubkeys, pubkey)
	}

	trustBundlesById, verifyErr := pol.TrustBundles()
	if verifyErr != nil {
		return nil, fmt.Errorf("failed to load policy trust bundles: %w", verifyErr)
	}

	roots := make([]*x509.Certificate, 0)
	intermediates := make([]*x509.Certificate, 0)
	for _, trustBundle := range trustBundlesById {
		roots = append(roots, trustBundle.Root)
		intermediates = append(intermediates, intermediates...)
	}

	timestampAuthoritiesById, verifyErr := pol.TimestampAuthorityTrustBundles()
	if verifyErr != nil {
		return nil, fmt.Errorf("failed to load policy timestamp authorities: %w", verifyErr)
	}

	timestampVerifiers := make([]dsse.TimestampVerifier, 0)
	for _, timestampAuthority := range timestampAuthoritiesById {
		certs := []*x509.Certificate{timestampAuthority.Root}
		certs = append(certs, timestampAuthority.Intermediates...)
		timestampVerifiers = append(timestampVerifiers, timestamp.NewVerifier(timestamp.VerifyWithCerts(certs)))
	}

	verifiedSource := source.NewVerifiedSource(
		vo.collectionSource,
		dsse.VerifyWithVerifiers(pubkeys...),
		dsse.VerifyWithRoots(roots...),
		dsse.VerifyWithIntermediates(intermediates...),
		dsse.VerifyWithTimestampVerifiers(timestampVerifiers...),
	)
	accepted, verifyErr := pol.Verify(ctx, policy.WithSubjectDigests(vo.subjectDigests), policy.WithVerifiedSource(verifiedSource))

	if verifyErr != nil {
		decisionErr := createPolicyDecision(vo, policy.DecisionDenied, policyEnvelope, accepted)
		if decisionErr != nil {
			return nil, fmt.Errorf("failed to verify policy and post decision: /n %v /n %w", verifyErr, decisionErr)
		}
		return nil, fmt.Errorf("failed to verify policy: %w", verifyErr)
	}

	decisionErr := createPolicyDecision(vo, policy.DecisionAllowed, policyEnvelope, accepted)
	if decisionErr != nil {
		return nil, fmt.Errorf("failed to post decision: /n %v", decisionErr)
	}

	return accepted, nil
}

// this creates a policy decision and sends it as a cloud event to your decision log url, if provided
func createPolicyDecision(vo verifyOptions, decision policy.Decision, policyEnvelope dsse.Envelope, evidence map[string][]source.VerifiedCollection) error {
	if vo.decisionLogURL == "" {
		return nil
	}

	policyEnvelopeBytes, err := json.Marshal(policyEnvelope)
	if err != nil {
		log.Errorf("failed to marshal policyEnvelope: %v", err)
		return err
	}

	gid, err := gitoid.New(bytes.NewReader(policyEnvelopeBytes), gitoid.WithContentLength(int64(len(policyEnvelopeBytes))), gitoid.WithSha256())
	if err != nil {
		log.Errorf("failed to generate gitoid: %v", err)
		return err
	}

	pd := policy.PolicyDecision{
		Digests:        vo.subjectDigests,
		Timestamp:      time.Now(), // TODO: Time Stamp Authority?
		Decision:       decision,
		PolicyGitoid:   string(gid.Bytes()),
		EvidenceHashes: make([]string, len(evidence)),
	}

	num := 0
	for _, stepEvidence := range evidence {
		for _, e := range stepEvidence {
			pd.EvidenceHashes[num] = string([]byte(e.Reference))
		}
	}

	event := cloudevents.NewEvent()
	c, err := cloudevents.NewClientHTTP()
	if err != nil {
		return fmt.Errorf("failed to create client, %v", err)
	}

	event.SetSource("/policy-decision")
	event.SetType("com.testifysec.policydecision")
	event.SetData(cloudevents.ApplicationJSON, fmt.Sprintf(`%#v`, pd))

	log.Infof("Policy decision created: %v", pd.Decision)

	err = postPolicyDecision(vo, event, c)
	if err != nil {
		return err
	}

	return nil
}

// this attempts to post the policy decision provided to the DecisionLogURL provided
func postPolicyDecision(vo verifyOptions, event cloudevents.Event, c cloudevents.Client) error {
	if vo.decisionLogURL == "" {
		return nil
	}
	ctx := cloudevents.ContextWithTarget(context.Background(), vo.decisionLogURL)
	log.Infof("Sending policy decision as payload of cloudevent to %v. Cloudevent payload: %s", vo.decisionLogURL, event)
	if result := c.Send(ctx, event); cloudevents.IsUndelivered(result) || cloudevents.IsNACK(result) {
		return fmt.Errorf("Failed to post policy decision to DecisionLogURL, %v", result)
	} else {
		log.Infof("sent: %v", event)
		log.Infof("result: %v", result)
		log.Info("Posted policy decision to DecisonLogURL successfully")
		return nil
	}
}
