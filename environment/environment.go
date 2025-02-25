// Copyright 2024 The Witness Contributors
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

package environment

import (
	"strings"
)

type Capture struct {
	sensitiveVarsList           map[string]struct{}
	addSensitiveVarsList        map[string]struct{}
	excludeSensitiveVarsList    map[string]struct{}
	filterVarsEnabled           bool
	disableSensitiveVarsDefault bool
}

type CaptureOption func(*Capture)

// WithFilterVarsEnabled will make the filter (removing) of vars the acting behavior.
// The default behavior is obfuscation of variables.
func WithFilterVarsEnabled() CaptureOption {
	return func(c *Capture) {
		c.filterVarsEnabled = true
	}
}

// WithAdditionalKeys add additional keys to final list that is checked for sensitive variables.
func WithAdditionalKeys(additionalKeys []string) CaptureOption {
	return func(c *Capture) {
		for _, value := range additionalKeys {
			c.addSensitiveVarsList[value] = struct{}{}
		}
	}
}

// WithExcludeKeys add additional keys to final list that is checked for sensitive variables.
func WithExcludeKeys(excludeKeys []string) CaptureOption {
	return func(c *Capture) {
		for _, value := range excludeKeys {
			c.excludeSensitiveVarsList[value] = struct{}{}
		}
	}
}

// WithDisableDefaultSensitiveList will disable the default list and only use the additional keys.
func WithDisableDefaultSensitiveList() CaptureOption {
	return func(c *Capture) {
		c.disableSensitiveVarsDefault = true
	}
}

func New(opts ...CaptureOption) *Capture {
	capture := &Capture{
		sensitiveVarsList:        DefaultSensitiveEnvList(),
		addSensitiveVarsList:     map[string]struct{}{},
		excludeSensitiveVarsList: map[string]struct{}{},
	}

	for _, opt := range opts {
		opt(capture)
	}

	return capture
}

func (c *Capture) Capture(env []string) map[string]string {
	variables := make(map[string]string)

	// Prepare sensitive keys list.
	var finalSensitiveKeysList map[string]struct{}
	if c.disableSensitiveVarsDefault {
		c.sensitiveVarsList = map[string]struct{}{}
	}
	finalSensitiveKeysList = c.sensitiveVarsList
	for k, v := range c.addSensitiveVarsList {
		finalSensitiveKeysList[k] = v
	}

	// Filter or obfuscate
	if c.filterVarsEnabled {
		FilterEnvironmentArray(env, finalSensitiveKeysList, c.excludeSensitiveVarsList, func(key, val, _ string) {
			variables[key] = val
		})
	} else {
		ObfuscateEnvironmentArray(env, finalSensitiveKeysList, c.excludeSensitiveVarsList, func(key, val, _ string) {
			variables[key] = val
		})
	}

	return variables
}

// splitVariable splits a string representing an environment variable in the format of
// "KEY=VAL" and returns the key and val separately.
func splitVariable(v string) (key, val string) {
	parts := strings.SplitN(v, "=", 2)
	key = parts[0]
	if len(parts) > 1 {
		val = parts[1]
	}

	return
}
