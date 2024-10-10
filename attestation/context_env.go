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

package attestation

import (
	env "github.com/in-toto/go-witness/environment"
)

func (ctx *AttestationContext) EnvironmentCapturer() *env.Capture {
	return ctx.environmentCapturer
}

// WithEnvFilterVarsEnabled will make the filter (removing) of vars the acting behavior.
// The default behavior is obfuscation of variables.
func WithEnvFilterVarsEnabled() AttestationContextOption {
	return func(a *AttestationContext) {
		env.WithFilterVarsEnabled()(a.environmentCapturer)
	}
}

// WithEnvAdditionalKeys add additional keys to final list that is checked for sensitive variables.
func WithEnvAdditionalKeys(additionalKeys []string) AttestationContextOption {
	return func(a *AttestationContext) {
		env.WithAdditionalKeys(additionalKeys)(a.environmentCapturer)
	}
}

// WithEnvExcludeKeys add additional keys to final list that is checked for sensitive variables.
func WithEnvExcludeKeys(excludeKeys []string) AttestationContextOption {
	return func(a *AttestationContext) {
		env.WithExcludeKeys(excludeKeys)(a.environmentCapturer)
	}
}

// WithEnvDisableDefaultSensitiveList will disable the default list and only use the additional keys.
func WithEnvDisableDefaultSensitiveList() AttestationContextOption {
	return func(a *AttestationContext) {
		env.WithDisableDefaultSensitiveList()(a.environmentCapturer)
	}
}
