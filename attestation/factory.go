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

	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/registry"
	"github.com/invopop/jsonschema"
)

var (
	attestorRegistry   = registry.New[Attestor]()
	attestationsByType = map[string]registry.Entry[Attestor]{}
	attestationsByRun  = map[RunType]registry.Entry[Attestor]{}
)

type Attestor interface {
	Name() string
	Type() string
	RunType() RunType
	Attest(ctx *AttestationContext) error
	Schema() *jsonschema.Schema
}

// Subjecter allows attestors to expose bits of information that will be added to
// the in-toto statement as subjects. External services such as Rekor and Archivista
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

// Exporter allows attestors to export their attestations for separation from the collection.
type Exporter interface {
	Export() bool
	Subjects() map[string]cryptoutil.DigestSet
}

// MultiExporter allows attestors to export multiple attestations, one for each item.
// This is useful for attestors that want to create individual attestations for each
// file or artifact they process, or to export subsets of data separately.
// Attestors implementing MultiExporter should also implement Exporter if they want
// to control whether they are included in the attestation collection.
// The returned attestors should be fully initialized and ready to have their
// Type(), Name(), and Subjecter.Subjects() methods called.
type MultiExporter interface {
	ExportedAttestations() []Attestor
}

// BackReffer allows attestors to indicate which of their subjects are good candidates
// to find related attestations.  For example the git attestor's commit hash subject
// is a good candidate to find all attestation collections that also refer to a specific
// git commit.
type BackReffer interface {
	BackRefs() map[string]cryptoutil.DigestSet
}

type ErrAttestationNotFound string

func (e ErrAttestationNotFound) Error() string {
	return fmt.Sprintf("attestation not found: %v", string(e))
}

type ErrAttestorNotFound string

func (e ErrAttestorNotFound) Error() string {
	return fmt.Sprintf("attestor not found: %v", string(e))
}

func RegisterAttestation(name, predicateType string, run RunType, factoryFunc registry.FactoryFunc[Attestor], opts ...registry.Configurer) {
	registrationEntry := attestorRegistry.Register(name, factoryFunc, opts...)
	attestationsByType[predicateType] = registrationEntry
	attestationsByRun[run] = registrationEntry
}

func RegisterAttestationWithTypes(name string, predicateTypes []string, run RunType, factoryFunc registry.FactoryFunc[Attestor], opts ...registry.Configurer) {
	registrationEntry := attestorRegistry.Register(name, factoryFunc, opts...)
	for _, predicateType := range predicateTypes {
		attestationsByType[predicateType] = registrationEntry
	}
	attestationsByRun[run] = registrationEntry
}

func FactoryByType(uri string) (registry.FactoryFunc[Attestor], bool) {
	registrationEntry, ok := attestationsByType[uri]
	return registrationEntry.Factory, ok
}

func FactoryByName(name string) (registry.FactoryFunc[Attestor], bool) {
	registrationEntry, ok := attestorRegistry.Entry(name)
	return registrationEntry.Factory, ok
}

func GetAttestor(nameOrType string) (Attestor, error) {
	attestors, err := GetAttestors([]string{nameOrType})
	if err != nil {
		return nil, err
	}

	if len(attestors) == 0 {
		return nil, ErrAttestorNotFound(nameOrType)
	}

	return attestors[0], nil
}

// Deprecated: use GetAttestors instead
func Attestors(nameOrTypes []string) ([]Attestor, error) {
	return GetAttestors(nameOrTypes)
}

func GetAttestors(nameOrTypes []string) ([]Attestor, error) {
	attestors := make([]Attestor, 0)
	for _, nameOrType := range nameOrTypes {
		factory, ok := FactoryByName(nameOrType)
		if !ok {
			factory, ok = FactoryByType(nameOrType)
			if !ok {
				return nil, ErrAttestorNotFound(nameOrType)
			}
		}

		attestor := factory()
		opts := AttestorOptions(nameOrType)
		attestor, err := attestorRegistry.SetDefaultVals(attestor, opts)
		if err != nil {
			return nil, err
		}

		attestors = append(attestors, attestor)
	}

	return attestors, nil
}

func AttestorOptions(nameOrType string) []registry.Configurer {
	entry, ok := attestorRegistry.Entry(nameOrType)
	if !ok {
		entry = attestationsByType[nameOrType]
	}

	return entry.Options
}

func RegistrationEntries() []registry.Entry[Attestor] {
	return attestorRegistry.AllEntries()
}
