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

package witness

import (
	"encoding/json"
	"fmt"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/environment"
	"github.com/in-toto/go-witness/attestation/git"
	"github.com/in-toto/go-witness/cryptoutil"
	idsse "github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/intoto"
	"github.com/in-toto/go-witness/signature/envelope"
	"github.com/in-toto/go-witness/signature/envelope/cose"
	dsse "github.com/in-toto/go-witness/signature/envelope/dsse"
)

type runOptions struct {
	stepName        string
	signer          cryptoutil.Signer
	envelopeType    string
	attestors       []attestation.Attestor
	attestationOpts []attestation.AttestationContextOption
	timestampers    []idsse.Timestamper
}

type RunOption func(ro *runOptions)

func RunWithEnvelopeType(envelopeType string) RunOption {
	return func(ro *runOptions) {
		ro.envelopeType = envelopeType
	}
}

func RunWithAttestors(attestors []attestation.Attestor) RunOption {
	return func(ro *runOptions) {
		ro.attestors = attestors
	}
}

func RunWithAttestationOpts(opts ...attestation.AttestationContextOption) RunOption {
	return func(ro *runOptions) {
		ro.attestationOpts = opts
	}
}

func RunWithTimestampers(ts ...idsse.Timestamper) RunOption {
	return func(ro *runOptions) {
		ro.timestampers = ts
	}
}

type RunResult struct {
	Collection     attestation.Collection
	SignedEnvelope envelope.Envelope
}

func Run(stepName string, signer cryptoutil.Signer, opts ...RunOption) (RunResult, error) {
	ro := runOptions{
		stepName:  stepName,
		signer:    signer,
		attestors: []attestation.Attestor{environment.New(), git.New()},
	}

	for _, opt := range opts {
		opt(&ro)
	}

	if ro.envelopeType == "" {
		return RunResult{}, fmt.Errorf("envelope type must be specified")
	}

	result := RunResult{}
	if err := validateRunOpts(ro); err != nil {
		return result, err
	}

	runCtx, err := attestation.NewContext(ro.attestors, ro.attestationOpts...)
	if err != nil {
		return result, fmt.Errorf("failed to create attestation context: %w", err)
	}

	if err := runCtx.RunAttestors(); err != nil {
		return result, fmt.Errorf("failed to run attestors: %w", err)
	}

	result.Collection = attestation.NewCollection(ro.stepName, runCtx.CompletedAttestors())
	se, err := signCollection(result.Collection, ro.signer, ro.envelopeType, ro.timestampers)
	if err != nil {
		return result, fmt.Errorf("failed to sign collection: %w", err)
	}

	result.SignedEnvelope = *se

	return result, nil
}

func validateRunOpts(ro runOptions) error {
	if ro.stepName == "" {
		return fmt.Errorf("step name is required")
	}

	if ro.signer == nil {
		return fmt.Errorf("signer is required")
	}

	return nil
}

// NOTE: The way payloads are being carried around won't be good for performance. needs optimization.
// NOTE: Needs refactored so Timestamper is genericized for compatibility with other envelope types
func signCollection(collection attestation.Collection, signer cryptoutil.Signer, envelopeType string, timestampers []idsse.Timestamper) (*envelope.Envelope, error) {
	data, err := json.Marshal(&collection)
	if err != nil {
		return nil, err
	}

	stmt, err := intoto.NewStatement(attestation.CollectionType, data, collection.Subjects())
	if err != nil {
		return nil, err
	}

	stmtJson, err := json.Marshal(&stmt)
	if err != nil {
		return nil, err
	}

	env, err := initEnvelope(envelopeType, intoto.PayloadType, &stmtJson)
	if err != nil {
		return nil, err
	}

	err = env.Sign(&signer, envelope.WithTimestampers(timestampers))
	if err != nil {
		return nil, err
	}

	return &env, nil
}

func initEnvelope(envelopeType string, payloadType string, stmtJson *[]byte) (envelope.Envelope, error) {
	var env envelope.Envelope
	var err error
	switch envelopeType {
	case "dsse":
		env, err = dsse.NewEnvelope(payloadType, *stmtJson)
		if err != nil {
			return nil, err
		}
	case "cose":
		env, err = cose.NewEnvelope(payloadType, *stmtJson)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("envelope type %s not recognized", envelopeType)
	}

	return env, nil
}
