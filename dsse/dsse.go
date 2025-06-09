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

package dsse

import (
	"fmt"

	"github.com/in-toto/go-witness/log"
)

type ErrNoSignatures struct{}

func (e ErrNoSignatures) Error() string {
	return "no signatures in dsse envelope"
}

type ErrNoMatchingSigs struct {
	Verifiers []CheckedVerifier
}

func (e ErrNoMatchingSigs) Error() string {
	mess := "no valid signatures for the provided verifiers found for keyids:\n"
	for _, v := range e.Verifiers {
		if v.Error != nil {
			kid, err := v.Verifier.KeyID()
			if err != nil {
				log.Warnf("failed to get key id from verifier: %w", err)
			}

			s := fmt.Sprintf("  %s: %v\n", kid, v.Error)
			mess += s
		}
	}

	return mess
}

type ErrThresholdNotMet struct {
	Theshold int
	Actual   int
}

func (e ErrThresholdNotMet) Error() string {
	return fmt.Sprintf("envelope did not meet verifier threshold. expected %v valid verifiers but got %v", e.Theshold, e.Actual)
}

type ErrInvalidThreshold int

func (e ErrInvalidThreshold) Error() string {
	return fmt.Sprintf("invalid threshold (%v). thresholds must be greater than 0", int(e))
}

const PemTypeCertificate = "CERTIFICATE"

type Envelope struct {
	Payload     []byte      `json:"payload" jsonschema:"title=Payload,description=Base64-encoded payload data"`
	PayloadType string      `json:"payloadType" jsonschema:"title=Payload Type,description=Media type describing the payload format,example=application/vnd.in-toto+json"`
	Signatures  []Signature `json:"signatures" jsonschema:"title=Signatures,description=List of signatures over the payload"`
}

type Signature struct {
	KeyID         string               `json:"keyid" jsonschema:"title=Key ID,description=Identifier of the key used to create this signature"`
	Signature     []byte               `json:"sig" jsonschema:"title=Signature,description=Base64-encoded signature value"`
	Certificate   []byte               `json:"certificate,omitempty" jsonschema:"title=Certificate,description=PEM-encoded signing certificate"`
	Intermediates [][]byte             `json:"intermediates,omitempty" jsonschema:"title=Intermediates,description=PEM-encoded intermediate certificates"`
	Timestamps    []SignatureTimestamp `json:"timestamps,omitempty" jsonschema:"title=Timestamps,description=Trusted timestamps for this signature"`
}

type SignatureTimestampType string

const TimestampRFC3161 SignatureTimestampType = "tsp"

type SignatureTimestamp struct {
	Type SignatureTimestampType `json:"type" jsonschema:"title=Type,description=Type of timestamp (e.g. tsp for RFC3161),enum=tsp"`
	Data []byte                 `json:"data" jsonschema:"title=Data,description=Base64-encoded timestamp data"`
}

// preauthEncode wraps the data to be signed or verified and it's type in the DSSE protocol's
// pre-authentication encoding as detailed at https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
// PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
func preauthEncode(bodyType string, body []byte) []byte {
	const dsseVersion = "DSSEv1"
	return []byte(fmt.Sprintf("%s %d %s %d %s", dsseVersion, len(bodyType), bodyType, len(body), body))
}
