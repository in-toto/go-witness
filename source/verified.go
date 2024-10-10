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

package source

import (
	"context"
	"fmt"

	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/dsse"
)

type CollectionVerificationResult struct {
	Verifiers          []cryptoutil.Verifier
	ValidFunctionaries []cryptoutil.Verifier
	CollectionEnvelope
	Errors   []error
	Warnings []string
}

type VerifiedSourcer interface {
	Search(ctx context.Context, collectionName string, subjectDigests, attestations []string) ([]CollectionVerificationResult, error)
}

type VerifiedSource struct {
	source     Sourcer
	verifyOpts []dsse.VerificationOption
}

func NewVerifiedSource(source Sourcer, verifyOpts ...dsse.VerificationOption) *VerifiedSource {
	return &VerifiedSource{source, verifyOpts}
}

func (s *VerifiedSource) Search(ctx context.Context, collectionName string, subjectDigests, attestations []string) ([]CollectionVerificationResult, error) {
	unverified, err := s.source.Search(ctx, collectionName, subjectDigests, attestations)
	if err != nil {
		return nil, err
	}

	results := make([]CollectionVerificationResult, 0)
	for _, toVerify := range unverified {
		envelopeVerifiers, err := toVerify.Envelope.Verify(s.verifyOpts...)
		if err != nil {
			results = append(results,
				CollectionVerificationResult{
					Errors:             []error{fmt.Errorf("failed to verify envelope: %w", err)},
					CollectionEnvelope: toVerify,
				},
			)
			continue
		}

		passedVerifiers := make([]cryptoutil.Verifier, 0)
		for _, verifier := range envelopeVerifiers {
			if verifier.Error == nil {
				passedVerifiers = append(passedVerifiers, verifier.Verifier)
			}
		}

		var Errors []error
		if len(passedVerifiers) == 0 {
			Errors = append(Errors, fmt.Errorf("no verifiers passed"))
		}

		results = append(results, CollectionVerificationResult{
			Verifiers:          passedVerifiers,
			CollectionEnvelope: toVerify,
			Errors:             Errors,
		})
	}

	return results, nil
}
