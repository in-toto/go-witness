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

package attestation

import (
	"fmt"

	"github.com/testifysec/go-witness/cryptoutil"
)

var (
	attestationsByName = map[string]AttestorFactory{}
	attestationsByType = map[string]AttestorFactory{}
	attestationsByRun  = map[string]AttestorFactory{}
)

type Attestor interface {
	Name() string
	Type() string
	RunType() RunType
	Attest(ctx *AttestationContext) error
}

// Subjecter allows attestors to expose bits of information that will be added to
// the in-toto statement as subjects. External services such as Rekor and Archivist
// use in-toto subjects as indexes back to attestations.
type Subjecter interface {
	Subjects() map[string]cryptoutil.DigestSet
}

// Materialer allows attestors to communicate about materials that were observed
// while the attestor executed. For example the material attestor records the hashes
// of all files before a command is run.
type Materialer interface {
	Materials() map[string]cryptoutil.DigestSet
}

// Producer allows attestors to communicate that some product was created while the
// attestor executed. For example the product attestor runs after a command run and
// finds files that did not exist in the working directory prior to the command's
// execution.
type Producer interface {
	Products() map[string]Product
}

// BackReffer allows attestors to indicate which of their subjects are good candidates
// to find related attestations.  For example the git attestor's commit hash subject
// is a good candidate to find all attestation collections that also refer to a specific
// git commit.
type BackReffer interface {
	BackRefs() map[string]cryptoutil.DigestSet
}

type AttestorFactory func() Attestor

type ErrAttestationNotFound string

func (e ErrAttestationNotFound) Error() string {
	return fmt.Sprintf("attestation not found: %v", string(e))
}

func RegisterAttestation(name, uri string, run RunType, factoryFunc AttestorFactory) {
	attestationsByName[name] = factoryFunc
	attestationsByType[uri] = factoryFunc
	attestationsByRun[run.String()] = factoryFunc
}

func FactoryByType(uri string) (AttestorFactory, bool) {
	factory, ok := attestationsByType[uri]
	return factory, ok
}

func FactoryByName(name string) (AttestorFactory, bool) {
	factory, ok := attestationsByName[name]
	return factory, ok
}

func Attestors(nameOrTypes []string) ([]Attestor, error) {
	attestors := make([]Attestor, 0)
	for _, nameOrType := range nameOrTypes {
		factory, ok := FactoryByName(nameOrType)
		if ok {
			attestors = append(attestors, factory())
			continue
		}

		factory, ok = FactoryByType(nameOrType)
		if ok {
			attestors = append(attestors, factory())
			continue
		}

		return nil, ErrAttestationNotFound(nameOrType)
	}

	return attestors, nil
}
