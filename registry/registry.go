// Copyright 2023 The Witness Contributors
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

package registry

import (
	"fmt"
	"time"

	"github.com/in-toto/go-witness/log"
)

// Registry is a way for the library to expose details about available configuration options
// for a collection of Entities at run time. This is useful to do things such as expose attestor
// configuration options to Witness CLI. This lets the CLI create flags for all the available
// options at run time.
type Registry[T any] struct {
	entriesByName map[string]Entry[T]
}

// FactoryFunc is a function that will create an instantiation of an Entity
type FactoryFunc[T any] func() T

// Entry contains information about each of the Entities in the Registry including the factory
// function, name, and configurable options
type Entry[T any] struct {
	Factory FactoryFunc[T]
	Name    string
	Options []Configurer
}

// New returns a new instance of a Registry
func New[T any]() Registry[T] {
	reg := Registry[T]{
		entriesByName: make(map[string]Entry[T]),
	}

	return reg
}

// Register adds an Entry to the Registry for an Entity
func (r Registry[T]) Register(name string, factoryFunc FactoryFunc[T], opts ...Configurer) Entry[T] {
	entry := Entry[T]{
		Name:    name,
		Factory: factoryFunc,
		Options: opts,
	}

	r.entriesByName[name] = entry
	return entry
}

// Options returns all of the available options an Entity with the provided name. If an Entity with the
// provided name cannot be found in the Registry the boolean return value will be false.
func (r Registry[T]) Options(name string) ([]Configurer, bool) {
	entry, ok := r.entriesByName[name]
	return entry.Options, ok
}

// Entry returns the Registry Entry for an Entity with the provided name. If an entity with the
// provided name cannot be found in the Registry, the boolean return value will be false.
func (r Registry[T]) Entry(name string) (Entry[T], bool) {
	entry, ok := r.entriesByName[name]
	return entry, ok
}

// AllEntries returns every Entry in the Registry
func (r Registry[T]) AllEntries() []Entry[T] {
	results := make([]Entry[T], 0, len(r.entriesByName))
	for _, registration := range r.entriesByName {
		results = append(results, registration)
	}

	return results
}

// NewEntity creates a new entity with the the default options set
func (r Registry[T]) NewEntity(name string, optSetters ...func(T) (T, error)) (T, error) {
	var result T
	entry, ok := r.Entry(name)
	if !ok {
		return result, fmt.Errorf("could not find entry with name %v", name)
	}

	result, err := SetDefaultVals(entry.Factory(), entry.Options)
	if err != nil {
		return result, fmt.Errorf("could not set default values: %w", err)
	}

	return SetOptions(result, optSetters...)
}

// NewEntityFromConfigMap creates a new entity with options provided by a config map.
// Values in the config map will be used to set options on the entity by the key of the config map.
func (r Registry[T]) NewEntityFromConfigMap(name string, configMap map[string]any) (T, error) {
	var result T
	entry, ok := r.Entry(name)
	if !ok {
		return result, fmt.Errorf("could not find entry with name %v", name)
	}

	result, err := SetDefaultVals(entry.Factory(), entry.Options)
	if err != nil {
		return result, fmt.Errorf("could not set default values: %w", err)
	}

	return SetOptionsFromConfigMap(result, entry.Options, configMap)
}

func SetOptions[T any](entity T, optSetters ...func(T) (T, error)) (T, error) {
	var err error
	result := entity
	for _, setter := range optSetters {
		result, err = setter(result)
		if err != nil {
			return result, err
		}
	}

	return result, err
}

// SetDefaultVals will take an Entity and call Setter for every option with that option's defaultVal.
func SetDefaultVals[T any](entity T, opts []Configurer) (T, error) {
	var err error

	for _, opt := range opts {
		switch o := opt.(type) {
		case *ConfigOption[T, int]:
			entity, err = o.Setter()(entity, o.DefaultVal())
		case *ConfigOption[T, string]:
			entity, err = o.Setter()(entity, o.DefaultVal())
		case *ConfigOption[T, []string]:
			entity, err = o.Setter()(entity, o.DefaultVal())
		case *ConfigOption[T, bool]:
			entity, err = o.Setter()(entity, o.DefaultVal())
		case *ConfigOption[T, time.Duration]:
			entity, err = o.Setter()(entity, o.DefaultVal())
		}

		if err != nil {
			return entity, err
		}
	}

	return entity, nil
}

func SetOptionsFromConfigMap[T any](entity T, configurers []Configurer, configMap map[string]any) (T, error) {
	optsByName := make(map[string]Configurer)
	for _, opt := range configurers {
		optsByName[opt.Name()] = opt
	}

	var err error
	for name, value := range configMap {
		opt, ok := optsByName[name]
		if !ok {
			log.Debugf("unknown option name in config map: %v", name)
			continue
		}

		switch o := opt.(type) {
		case *ConfigOption[T, int]:
			val, ok := value.(int)
			if !ok {
				return entity, fmt.Errorf("expected value for option %v to be an int but got %T", name, value)
			}
			entity, err = o.Setter()(entity, val)
		case *ConfigOption[T, string]:
			val, ok := value.(string)
			if !ok {
				return entity, fmt.Errorf("expected value for option %v to be an int but got %T", name, value)
			}
			entity, err = o.Setter()(entity, val)
		case *ConfigOption[T, []string]:
			val, ok := value.([]string)
			if !ok {
				return entity, fmt.Errorf("expected value for option %v to be an int but got %T", name, value)
			}
			entity, err = o.Setter()(entity, val)
		case *ConfigOption[T, bool]:
			val, ok := value.(bool)
			if !ok {
				return entity, fmt.Errorf("expected value for option %v to be an int but got %T", name, value)
			}
			entity, err = o.Setter()(entity, val)
		case *ConfigOption[T, time.Duration]:
			val, ok := value.(time.Duration)
			if !ok {
				return entity, fmt.Errorf("expected value for option %v to be an int but got %T", name, value)
			}
			entity, err = o.Setter()(entity, val)
		}

		if err != nil {
			return entity, err
		}
	}

	return entity, nil
}
