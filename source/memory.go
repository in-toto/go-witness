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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/testifysec/go-witness/dsse"
)

type ErrDuplicateReference string

func (e ErrDuplicateReference) Error() string {
	return fmt.Sprintf("references may only appear once in a memory source: %v", string(e))
}

type MemorySource struct {
	envelopesByReference       map[string]CollectionEnvelope
	referencesByCollectionName map[string][]string
	referencesBySubjectDigest  map[string][]string
	attestationsByReference    map[string]struct{}
}

func NewMemorySource() *MemorySource {
	return &MemorySource{
		envelopesByReference:       make(map[string]CollectionEnvelope),
		referencesByCollectionName: make(map[string][]string),
		referencesBySubjectDigest:  make(map[string][]string),
		attestationsByReference:    make(map[string]struct{}),
	}
}

func (s *MemorySource) LoadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}

	defer f.Close()
	return s.LoadReader(path, f)
}

func (s *MemorySource) LoadReader(reference string, r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	return s.LoadBytes(reference, data)
}

func (s *MemorySource) LoadBytes(reference string, data []byte) error {
	env := dsse.Envelope{}
	if err := json.Unmarshal(data, &env); err != nil {
		return err
	}

	return s.LoadEnvelope(reference, env)
}

func (s *MemorySource) LoadEnvelope(reference string, env dsse.Envelope) error {
	if _, ok := s.envelopesByReference[reference]; ok {
		return ErrDuplicateReference(reference)
	}

	collEnv, err := envelopeToCollectionEnvelope(reference, env)
	if err != nil {
		return err
	}

	s.envelopesByReference[reference] = collEnv
	s.referencesByCollectionName[collEnv.Collection.Name] = append(s.referencesByCollectionName[collEnv.Collection.Name], reference)

	// Add the reference to the map of references by subject digest for each subject in the statement
	for _, sub := range collEnv.Statement.Subject {
		for _, digest := range sub.Digest {
			s.referencesBySubjectDigest[digest] = append(s.referencesBySubjectDigest[digest], reference)
		}
	}

	// Sort the attestations in the collection envelope by their type
	sort.Slice(collEnv.Collection.Attestations, func(i, j int) bool {
		return collEnv.Collection.Attestations[i].Attestation.Type() < collEnv.Collection.Attestations[j].Attestation.Type()
	})

	// Compress the attestations into a key for quick lookup
	attkey := ""
	for _, att := range collEnv.Collection.Attestations {
		attkey += att.Attestation.Type()
	}

	// Add the attestation key to the map of attestations by reference
	s.attestationsByReference[reference+attkey] = struct{}{}
	return nil
}

func (s *MemorySource) Search(ctx context.Context, collectionName string, subjectDigests, attestations []string) ([]CollectionEnvelope, error) {
	// Initialize an empty slice to store matching envelopes
	matches := []CollectionEnvelope{}

	// Sort attestations and join them into a key
	sort.Strings(attestations)
	attestationKey := strings.Join(attestations, "")

	// Initialize a map to store potential matches
	potentialMatches := map[string]struct{}{}

	// Populate the map with references from subject digests
	for _, subjectDigest := range subjectDigests {
		for _, reference := range s.referencesBySubjectDigest[subjectDigest] {
			potentialMatches[reference] = struct{}{}
		}
	}

	// Iterate over potential matches and check if they exist in the envelopes by reference
	for reference := range potentialMatches {
		envelope, envelopeExists := s.envelopesByReference[reference]

		// Check if all the expected attestations appear in the collection and the envelope exist in the memory source
		if _, containsNecessaryAttestations := s.attestationsByReference[reference+attestationKey]; !containsNecessaryAttestations || !envelopeExists {
			continue
		}

		// If all checks pass, append the envelope to matches
		matches = append(matches, envelope)
	}

	return matches, nil
}
