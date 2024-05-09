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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/intoto"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/timestamp"
)

type runOptions struct {
	stepName        string
	signers         []cryptoutil.Signer
	attestors       []attestation.Attestor
	attestationOpts []attestation.AttestationContextOption
	timestampers    []timestamp.Timestamper
	insecure        bool
}

type RunOption func(ro *runOptions)

// RunWithInsecure will allow attestations to be generated unsigned. If insecure is true, RunResult will not
// contain a signed DSSE envelope
func RunWithInsecure(insecure bool) RunOption {
	return func(ro *runOptions) {
		ro.insecure = insecure
	}
}

// RunWithAttestors defines which attestors should be run and added to the resulting AttestationCollection
func RunWithAttestors(attestors []attestation.Attestor) RunOption {
	return func(ro *runOptions) {
		ro.attestors = append(ro.attestors, attestors...)
	}
}

// RunWithAttestationOpts takes in any AttestationContextOptions and forwards them to the context that Run
// creates
func RunWithAttestationOpts(opts ...attestation.AttestationContextOption) RunOption {
	return func(ro *runOptions) {
		ro.attestationOpts = opts
	}
}

// RunWithTimestampers will timestamp any signatures created on the DSSE time envelope with the provided
// timestampers
func RunWithTimestampers(ts ...timestamp.Timestamper) RunOption {
	return func(ro *runOptions) {
		ro.timestampers = ts
	}
}

// RunWithSigners configures the signers that will be used to sign the DSSE envelope containing the generated
// attestation collection.
func RunWithSigners(signers ...cryptoutil.Signer) RunOption {
	return func(ro *runOptions) {
		ro.signers = append(ro.signers, signers...)
	}
}

// RunResult contains the generated attestation collection as well as the signed DSSE envelope, if one was
// created.
type RunResult struct {
	Collection     attestation.Collection
	SignedEnvelope dsse.Envelope
	AttestorName   string
}

// Deprecated: Use RunWithExports instead
func Run(stepName string, opts ...RunOption) (RunResult, error) {
	results, err := run(stepName, opts)
	if len(results) > 1 {
		return RunResult{}, errors.New("expected a single result, got multiple")
	}
	return results[0], err
}

func RunWithExports(stepName string, opts ...RunOption) ([]RunResult, error) {
	return run(stepName, opts)
}

func run(stepName string, opts []RunOption) ([]RunResult, error) {
	ro := runOptions{
		stepName: stepName,
		insecure: false,
	}

	for _, opt := range opts {
		opt(&ro)
	}

	result := []RunResult{}
	if err := validateRunOpts(ro); err != nil {
		return result, err
	}

	runCtx, err := attestation.NewContext(stepName, ro.attestors, ro.attestationOpts...)
	if err != nil {
		return result, fmt.Errorf("failed to create attestation context: %w", err)
	}

	if err = runCtx.RunAttestors(); err != nil {
		return result, fmt.Errorf("failed to run attestors: %w", err)
	}

	errs := make([]error, 0)
	for _, r := range runCtx.CompletedAttestors() {
		if r.Error != nil {
			errs = append(errs, r.Error)
		} else {
			if exporter, ok := r.Attestor.(attestation.Exporter); ok {
				if !exporter.Export() {
					log.Debugf("%s attestor not configured to be exported as its own attestation", r.Attestor.Name())
					continue
				}
				if subjecter, ok := r.Attestor.(attestation.Subjecter); ok {
					envelope, err := createAndSignEnvelope(r.Attestor, r.Attestor.Type(), subjecter.Subjects(), dsse.SignWithSigners(ro.signers...), dsse.SignWithTimestampers(ro.timestampers...))
					if err != nil {
						return result, fmt.Errorf("failed to sign envelope: %w", err)
					}
					result = append(result, RunResult{SignedEnvelope: envelope, AttestorName: r.Attestor.Name()})
				}
			}
		}
	}

	if len(errs) > 0 {
		errs := append([]error{errors.New("attestors failed with error messages")}, errs...)
		return result, errors.Join(errs...)
	}

	var collectionResult RunResult
	collectionResult.Collection = attestation.NewCollection(ro.stepName, runCtx.CompletedAttestors())
	if !ro.insecure {
		collectionResult.SignedEnvelope, err = createAndSignEnvelope(collectionResult.Collection, attestation.CollectionType, collectionResult.Collection.Subjects(), dsse.SignWithSigners(ro.signers...), dsse.SignWithTimestampers(ro.timestampers...))
		if err != nil {
			return result, fmt.Errorf("failed to sign collection: %w", err)
		}
	}
	result = append(result, collectionResult)

	return result, nil
}

func validateRunOpts(ro runOptions) error {
	if ro.stepName == "" {
		return fmt.Errorf("step name is required")
	}

	if len(ro.signers) == 0 && !ro.insecure {
		return fmt.Errorf("at lease one signer is required if not in insecure mode")
	}

	return nil
}

func createAndSignEnvelope(predicate interface{}, predType string, subjects map[string]cryptoutil.DigestSet, opts ...dsse.SignOption) (dsse.Envelope, error) {
	data, err := json.Marshal(&predicate)
	if err != nil {
		return dsse.Envelope{}, err
	}

	stmt, err := intoto.NewStatement(predType, data, subjects)
	if err != nil {
		return dsse.Envelope{}, err
	}

	stmtJson, err := json.Marshal(&stmt)
	if err != nil {
		return dsse.Envelope{}, err
	}

	return dsse.Sign(intoto.PayloadType, bytes.NewReader(stmtJson), opts...)
}
