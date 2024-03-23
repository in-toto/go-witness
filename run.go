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
	"github.com/in-toto/go-witness/attestation/environment"
	"github.com/in-toto/go-witness/attestation/git"
	"github.com/in-toto/go-witness/attestation/link"
	"github.com/in-toto/go-witness/attestation/slsa"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/intoto"
	"github.com/in-toto/go-witness/timestamp"
)

type runOptions struct {
	stepName        string
	signer          cryptoutil.Signer
	attestors       []attestation.Attestor
	attestationOpts []attestation.AttestationContextOption
	timestampers    []timestamp.Timestamper
}

type RunOption func(ro *runOptions)

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

func RunWithTimestampers(ts ...timestamp.Timestamper) RunOption {
	return func(ro *runOptions) {
		ro.timestampers = ts
	}
}

type RunResult struct {
	Collection     attestation.Collection
	SignedEnvelope dsse.Envelope
	AttestorName   string
}

// Should this be deprecated?
// Deprecated: Use RunWithExports instead
func Run(stepName string, signer cryptoutil.Signer, opts ...RunOption) (RunResult, error) {
	results, err := run(stepName, signer, opts)
	if len(results) > 1 {
		return RunResult{}, errors.New("expected a single result, got multiple")
	}
	return results[0], err
}

func RunWithExports(stepName string, signer cryptoutil.Signer, opts ...RunOption) ([]RunResult, error) {
	return run(stepName, signer, opts)
}

func run(stepName string, signer cryptoutil.Signer, opts []RunOption) ([]RunResult, error) {
	ro := runOptions{
		stepName:  stepName,
		signer:    signer,
		attestors: []attestation.Attestor{environment.New(), git.New()},
	}

	for _, opt := range opts {
		opt(&ro)
	}

	result := []RunResult{}
	if err := validateRunOpts(ro); err != nil {
		return result, err
	}

	runCtx, err := attestation.NewContext(ro.attestors, ro.attestationOpts...)
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
		} else if r.Attestor.Name() == link.Name {
			// TODO: Find a better way to set stepName
			r.Attestor.(*link.Link).PbLink.Name = ro.stepName

			// TODO: Add Exporter interface to attestors
			if r.Attestor.(*link.Link).Export() {
				if subjecter, ok := r.Attestor.(attestation.Subjecter); ok {
					linkEnvelope, err := createAndSignEnvelope(r.Attestor, r.Attestor.Type(), subjecter.Subjects(), dsse.SignWithSigners(ro.signer), dsse.SignWithTimestampers(ro.timestampers...))
					if err != nil {
						return result, fmt.Errorf("failed to sign envelope: %w", err)
					}
					result = append(result, RunResult{SignedEnvelope: linkEnvelope, AttestorName: r.Attestor.Name()})
				}
			}
		} else if r.Attestor.Name() == slsa.Name {
			// TODO: Add Exporter interface to attestors
			if r.Attestor.(*slsa.Provenance).Export() {
				if subjecter, ok := r.Attestor.(attestation.Subjecter); ok {
					linkEnvelope, err := createAndSignEnvelope(r.Attestor, r.Attestor.Type(), subjecter.Subjects(), dsse.SignWithSigners(ro.signer), dsse.SignWithTimestampers(ro.timestampers...))
					if err != nil {
						return result, fmt.Errorf("failed to sign envelope: %w", err)
					}
					result = append(result, RunResult{SignedEnvelope: linkEnvelope, AttestorName: r.Attestor.Name()})
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
	collectionResult.SignedEnvelope, err = createAndSignEnvelope(collectionResult.Collection, attestation.CollectionType, collectionResult.Collection.Subjects(), dsse.SignWithSigners(ro.signer), dsse.SignWithTimestampers(ro.timestampers...))
	if err != nil {
		return result, fmt.Errorf("failed to sign collection: %w", err)
	}
	result = append(result, collectionResult)

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

func createAndSignEnvelope(collection interface{}, predType string, subjects map[string]cryptoutil.DigestSet, opts ...dsse.SignOption) (dsse.Envelope, error) {
	data, err := json.Marshal(&collection)
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
