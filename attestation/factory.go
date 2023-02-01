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
	"reflect"

	"github.com/davecgh/go-spew/spew"
	"github.com/testifysec/go-witness/cryptoutil"
)

var (
	attestationsByName = map[string]AttestorFactory{}
	attestationsByType = map[string]AttestorFactory{}
	attestationsByRun  = map[string]AttestorFactory{}
	attestorConfigs    = AttestorConfigs{}
)

type AttestorConfigs map[string]map[string]any

type Attestor interface {
	Name() string
	Type() string
	RunType() RunType
	Attest(ctx *AttestationContext) error
}

type Configurable interface {
	GetConfig() any
	SetConfig(c any) error
}

func RegisterAttestation(name string, uri string, run RunType, factoryFunc AttestorFactory) {
	attestationsByName[name] = factoryFunc
	attestationsByType[uri] = factoryFunc
	attestationsByRun[run.String()] = factoryFunc

	//check to see if the attestior is configurable
	a := factoryFunc()

	if c, ok := a.(Configurable); ok {
		conf := c.GetConfig()

		v := reflect.ValueOf(conf)

		typ := v.Type()
		for i := 0; i < v.NumField(); i++ {
			fi := typ.Field(i)
			fieldName := fi.Name
			value := v.Field(i).Interface()

			// Create a map entry for this attestor if it doesn't exist
			if _, ok := attestorConfigs[name]; !ok {
				attestorConfigs[name] = make(map[string]interface{})
			}

			attestorConfigs[name][fieldName] = value
		}
	}
	spew.Dump(attestorConfigs)
}

func RegisterConfig(attestors []Attestor, attestorConfig map[string]map[string]interface{}) {
	for _, attestor := range attestors {
		if c, ok := attestor.(Configurable); ok {
			name := reflect.TypeOf(attestor).Name()
			if config, ok := attestorConfig[name]; ok {
				c.SetConfig(config)
			}
		}
	}
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

func SetConfigHelper(v reflect.Value, t reflect.Type, c map[string]interface{}) error {
	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		fieldName := field.Name
		if value, ok := c[fieldName]; ok {
			f := v.FieldByName(fieldName)
			if f.CanSet() {
				fieldType := f.Type()
				switch fieldType.Kind() {
				case reflect.String:
					f.SetString(value.(string))
				case reflect.Int:
					f.SetInt(int64(value.(int)))
				case reflect.Slice:
					if fieldType.Elem().Kind() == reflect.String {
						sliceValue := value.([]interface{})
						strSlice := make([]string, len(sliceValue))
						for i, v := range sliceValue {
							strSlice[i] = v.(string)
						}
						f.Set(reflect.ValueOf(strSlice))
					} else {
						return fmt.Errorf("unsupported slice type")
					}
				default:
					return fmt.Errorf("unsupported field type")
				}
			}
		}
	}

	return nil
}
