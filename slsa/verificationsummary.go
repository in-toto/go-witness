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

package slsa

import (
	"time"

	"github.com/testifysec/go-witness/cryptoutil"
)

const (
	VerificationSummaryPredicate                    = "https://slsa.dev/verification_summary/v1"
	PassedVerificationResult     VerificationResult = "PASSED"
	FailedVerificationResult     VerificationResult = "FAILED"
)

type VerificationResult string

type Verifier struct {
	ID string `json:"id"`
}

type ResourceDescriptor struct {
	URI    string               `json:"uri"`
	Digest cryptoutil.DigestSet `json:"digest"`
}

type VerificationSummary struct {
	Verifier           Verifier             `json:"verifier"`
	TimeVerified       time.Time            `json:"timeVerified"`
	Policy             ResourceDescriptor   `json:"policy"`
	InputAttestations  []ResourceDescriptor `json:"inputAttestations"`
	VerificationResult VerificationResult   `json:"verificationResult"`
}
