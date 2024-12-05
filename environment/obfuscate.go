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

	"github.com/gobwas/glob"
	"github.com/in-toto/go-witness/log"
)

// FilterEnvironmentArray expects an array of strings representing environment variables.  Each element of the array is expected to be in the format of "KEY=VALUE".
// blockList is the list of elements to filter from variables, and for each element of variables that does not appear in the blockList onAllowed will be called.
func ObfuscateEnvironmentArray(variables []string, obfuscateList map[string]struct{}, excludeKeys map[string]struct{}, onAllowed func(key, val, orig string)) {
	obfuscateGlobList := []glob.Glob{}

	for k := range obfuscateList {
		if strings.Contains(k, "*") {
			obfuscateGlobCompiled, err := glob.Compile(k)
			if err != nil {
				log.Errorf("obfuscate glob pattern could not be interpreted: %w", err)
			}

			obfuscateGlobList = append(obfuscateGlobList, obfuscateGlobCompiled)
		}
	}

	for _, v := range variables {
		key, val := splitVariable(v)

		if _, inExcludKeys := excludeKeys[key]; !inExcludKeys {
			if _, inObfuscateList := obfuscateList[key]; inObfuscateList {
				val = "******"
			}

			for _, glob := range obfuscateGlobList {
				if glob.Match(key) {
					val = "******"
				}
			}
		}

		onAllowed(key, val, v)
	}
}
