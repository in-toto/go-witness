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

package vex

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/in-toto/go-witness/attestation"
	vex "github.com/openvex/go-vex/pkg/vex"
)

// NOTE(nick): examples https://github.com/openvex/vexctl/tree/main/examples/openvex

const vexDocumentExpected = `{
  "vexDocument": {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": "https://openvex.dev/docs/public/vex-0f3be8817faafa24e4bfb3d17eaf619efb1fe54923b9c42c57b156a936b91431",
    "author": "John Doe",
    "role": "Senior Trusted Vex Issuer",
    "timestamp": "1970-01-01T00:00:00Z",
    "version": 1,
    "statements": [
      {
        "vulnerability": {
          "name": "CVE-1234-5678"
        },
        "products": [
          {
            "@id": "pkg:apk/wolfi/bash@1.0.0"
          }
        ],
        "status": "fixed"
      }
    ]
  }
}`

func TestAttest(t *testing.T) {
	vexAttestor := New()
	vexAttestor.VEXDocument.Context = "https://openvex.dev/ns/v0.2.0"
	vexAttestor.VEXDocument.ID = "https://openvex.dev/docs/public/vex-0f3be8817faafa24e4bfb3d17eaf619efb1fe54923b9c42c57b156a936b91431"
	vexAttestor.VEXDocument.Author = "John Doe"
	vexAttestor.VEXDocument.AuthorRole = "Senior Trusted Vex Issuer"
	vexAttestor.VEXDocument.Version = 1
	time := time.Date(1970, 1, 1, 0, 0, 0, 0, time.Now().UTC().Location())
	vexAttestor.VEXDocument.Timestamp = &time
	vexAttestor.VEXDocument.Statements = []vex.Statement{
		{
			Vulnerability: vex.Vulnerability{
				Name: "CVE-1234-5678",
			},
			Products: []vex.Product{
				{
					Component: vex.Component{
						ID: "pkg:apk/wolfi/bash@1.0.0",
					},
				},
			},
			Status: vex.StatusFixed,
		},
	}

	attestorCollection := []attestation.Attestor{vexAttestor}
	ctx, err := attestation.NewContext("test", append(attestorCollection, vexAttestor))
	if err != nil {
		t.Errorf("error creating attestation context: %s", err)
	}
	err = ctx.RunAttestors()
	if err != nil {
		t.Errorf("error attesting: %s", err.Error())
	}

	vexDocJSON, err := json.MarshalIndent(vexAttestor, "", "  ")
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	expectedJSON := []byte(vexDocumentExpected)

	if !bytes.Equal(vexDocJSON, expectedJSON) {
		t.Errorf("expected \n%s\n, got \n%s\n", expectedJSON, vexDocJSON)
	}
}
