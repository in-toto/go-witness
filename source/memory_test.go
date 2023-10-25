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

package source

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/testifysec/go-witness/attestation"
	"github.com/testifysec/go-witness/dsse"
	intoto "github.com/testifysec/go-witness/intoto"
)

func TestLoadFile(t *testing.T) {
	predicate, err := json.Marshal(attestation.Collection{})
	if err != nil {
		fmt.Errorf("failed to marshal predicate, err = %v", err)
	}
	tests := []struct {
		name                 string
		reference            string
		intotoStatment       intoto.Statement
		mSource              *MemorySource
		attCol               attestation.Collection
		wantLoadEnvelopeErr  bool
		wantPredicateErr     bool
		wantMemorySourceErr  bool
		wantRefrenceExistErr bool
	}{
		{
			name:      "Valid intotoStatment",
			reference: "ref",
			intotoStatment: intoto.Statement{
				Type:          "https://in-toto.io/Statement/v0.1",
				Subject:       []intoto.Subject{{Name: "example", Digest: map[string]string{"sha256": "exampledigest"}}},
				PredicateType: "https://slsa.dev/provenance/v0.2",
				Predicate:     json.RawMessage(predicate),
			},
			attCol:  attestation.Collection{},
			mSource: NewMemorySource(),
		},
		{
			name:                "Empty Invalid intotoStatment",
			reference:           "ref",
			intotoStatment:      intoto.Statement{},
			mSource:             NewMemorySource(),
			attCol:              attestation.Collection{},
			wantPredicateErr:    true,
			wantMemorySourceErr: true,
		},
		{
			name:      "Invalid intotoStatment Predicate",
			reference: "ref",
			intotoStatment: intoto.Statement{
				Type:          "https://in-toto.io/Statement/v0.1",
				Subject:       []intoto.Subject{{Name: "example", Digest: map[string]string{"sha256": "exampledigest"}}},
				PredicateType: "https://slsa.dev/provenance/v0.2",
				Predicate:     json.RawMessage("invalid-predicate"),
			},
			attCol:              attestation.Collection{},
			mSource:             NewMemorySource(),
			wantLoadEnvelopeErr: true,
			wantMemorySourceErr: true,
		},
		{
			name:      "Valid intotoStatment",
			reference: "ref",
			intotoStatment: intoto.Statement{
				Type:          "https://in-toto.io/Statement/v0.1",
				Subject:       []intoto.Subject{{Name: "example", Digest: map[string]string{"sha256": "exampledigest"}}},
				PredicateType: "https://slsa.dev/provenance/v0.2",
				Predicate:     json.RawMessage(predicate),
			},
			mSource:              NewMemorySource(),
			wantLoadEnvelopeErr:  true,
			wantRefrenceExistErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Marshal the intoto.Statement into a JSON byte array
			var err error

			statementBytes, _ := json.Marshal(tt.intotoStatment)

			// Create a new dsse.Envelope with the marshalled intoto.Statement as the payload
			envelope := dsse.Envelope{
				Payload:     statementBytes,
				PayloadType: "application/vnd.in-toto+json",
			}

			// Initialize a new MemorySource
			memorySource := NewMemorySource()
			if tt.wantRefrenceExistErr {
				collEnv, err := envelopeToCollectionEnvelope(tt.reference, envelope)
				if err != nil {
					t.Errorf("Invalid intotoStatment, err = %v", err)
				}
				// since this envelope is not in the MemorySource, we can add the collection envelope into the map
				memorySource.envelopesByReference[tt.reference] = collEnv
			}

			// Load the dsse.Envelope into the MemorySource
			err = memorySource.LoadEnvelope(tt.reference, envelope)
			if err != nil {
				// if we did not want the error
				if !tt.wantLoadEnvelopeErr {
					t.Errorf("LoadEnvelope() error = %v, wantErr %v", err, tt.wantLoadEnvelopeErr)
					return
				}
				return

			}

			// Check if the loaded envelope matches the expected CollectionEnvelope

			expectedCollectionEnvelope := CollectionEnvelope{
				Envelope:   envelope,
				Statement:  tt.intotoStatment,
				Collection: tt.attCol,
				Reference:  tt.reference,
			}
			if !reflect.DeepEqual(memorySource.envelopesByReference[tt.reference], expectedCollectionEnvelope) != tt.wantMemorySourceErr {
				t.Errorf("Mismatch or non-existence of collection envelope for reference in envelopesByReference map.")
				return
			}
			// Verify if the subjects and attestations are present in the loaded envelope
			for _, sub := range tt.intotoStatment.Subject {
				for _, digest := range sub.Digest {
					if _, ok := memorySource.subjectDigestsByReference[tt.reference][digest]; !ok != tt.wantMemorySourceErr {
						t.Errorf("memorySource does not contain passed in digest = %v", digest)
						return
					}
				}
			}
			for _, att := range tt.attCol.Attestations {
				if _, ok := memorySource.attestationsByReference[tt.reference][att.Attestation.Type()]; !ok != tt.wantMemorySourceErr {
					t.Errorf("memorySource does not contain passed in attestation = %v", att.Attestation.Name())
					return
				}
			}

		})
	}
}
