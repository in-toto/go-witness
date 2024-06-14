// Copyright 2024 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sbom

import (
	"os"
	"strings"
	"testing"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/product"
)

func TestName(t *testing.T) {
	provenance := NewSBOMAttestor()
	if provenance.Name() != Name {
		t.Errorf("expected %s, got %s", Name, provenance.Name())
	}
}

func TestType(t *testing.T) {
	provenance := NewSBOMAttestor()
	if provenance.Type() != Type {
		t.Errorf("expected %s, got %s", Type, provenance.Type())
	}
}

func TestRunType(t *testing.T) {
	provenance := NewSBOMAttestor()
	if provenance.RunType() != RunType {
		t.Errorf("expected %s, got %s", RunType, provenance.RunType())
	}
}

func TestExport(t *testing.T) {
	sbom := NewSBOMAttestor()
	if sbom.export != defaultExport {
		t.Errorf("expected %t, got %t", defaultExport, sbom.export)
	}

	WithExport(true)(sbom)
	if !sbom.export {
		t.Errorf("expected %t, got %t", true, sbom.export)
	}

	if sbom.Export() != true {
		t.Errorf("expected %t, got %t", true, sbom.Export())
	}
}

func TestAttest(t *testing.T) {
	var tests = []struct {
		name          string
		sbomPath      string
		sbomFileName  string
		expectedType  string
		expectedError string
	}{
		{"SPDX 2.2", "./boms/spdx-2.2/", "alpine.spdx-2-2.json", SPDXPredicateType, ""},
		{"SPDX 2.3", "./boms/spdx-2.3/", "alpine.spdx-2-3.json", SPDXPredicateType, ""},
		{"CycloneDx", "./boms/cyclonedx-json/", "alpine.cyclonedx.json", CycloneDxPredicateType, ""},
		{"CycloneDx XML", "./boms/cyclonedx-xml/", "alpine.cyclonedx.xml", Type, "no SBOM file found"},
		{"Bad JSON", "./boms/bad-json/", "bad.json", SPDXPredicateType, "no SBOM file found"},
		{"No JSON", "./boms/emptyDir", "no.json", Type, "no products to attest"},
	}

	err := os.Mkdir("emptyDir", 0777)
	if err != nil && !os.IsExist(err) {
		t.Errorf("could not create empty directory: %s", err.Error())
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sbom := NewSBOMAttestor()
			p := product.New()

			ctx, err := attestation.NewContext("test", []attestation.Attestor{p, sbom},
				attestation.WithWorkingDir(test.sbomPath))
			if err != nil {
				t.Errorf("error creating attestation context: %s", err)
			}

			if err := ctx.RunAttestors(); err != nil {
				t.Errorf("unexpected error: %s", err)
			}

			if sbom.predicateType != test.expectedType {
				t.Errorf("expected SBOM type %s, got %s", test.expectedType, sbom.predicateType)
			}

			for _, a := range ctx.CompletedAttestors() {
				if a.Attestor.Name() == sbom.Name() {
					if a.Error != nil &&
						!strings.HasPrefix(a.Error.Error(), test.expectedError) {
						t.Errorf("expected error: %s, got %s", test.expectedError, a.Error.Error())
					}
				}
			}

			if test.expectedError == "" &&
				sbom.Subjects()["file:"+test.sbomFileName] == nil {
				t.Errorf("expected subject %s, got nil", test.sbomFileName)
			}
		})
	}
}

var testGoodSBOMs = []string{
	"./boms/spdx-2.2/alpine.spdx-2-2.json",
	"./boms/spdx-2.3/alpine.spdx-2-3.json",
	"./boms/cyclonedx-json/alpine.cyclonedx.json",
}

func TestUnmarshalJSON(t *testing.T) {
	sbom := NewSBOMAttestor()

	for _, testSBOM := range testGoodSBOMs {
		json, err := os.ReadFile(testSBOM)
		if err != nil {
			t.Errorf("could not read test sbom: %s", err.Error())
		}

		if err := sbom.UnmarshalJSON(json); err != nil {
			t.Errorf("unexpected error: %s", err)
		}
	}
}

func TestUnmarshalBadJSON(t *testing.T) {
	sbom := NewSBOMAttestor()

	json, err := os.ReadFile("./boms/cyclonedx-xml/alpine.cyclonedx.xml")
	if err != nil {
		t.Errorf("could not read test sbom: %s", err.Error())
	}

	if err := sbom.UnmarshalJSON(json); err == nil {
		t.Error("Expected error")
	}
}

func TestMarshalJSON(t *testing.T) {
	sbom := NewSBOMAttestor()

	for _, testSBOM := range testGoodSBOMs {
		json, err := os.ReadFile(testSBOM)
		if err != nil {
			t.Errorf("could not read test sbom: %s", err.Error())
		}

		if err := sbom.UnmarshalJSON(json); err != nil {
			t.Errorf("unexpected error: %s", err)
		}

		_, err = sbom.MarshalJSON()
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
	}
}
