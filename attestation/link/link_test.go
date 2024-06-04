// Copyright 2022 The Witness Contributors
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

package link

import (
	"bytes"
	"crypto"
	"encoding/json"
	"testing"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/internal/attestors"
)

func TestName(t *testing.T) {
	link := New()
	if link.Name() != Name {
		t.Errorf("expected %s, got %s", Name, link.Name())
	}
}

func TestType(t *testing.T) {
	link := New()
	if link.Type() != Type {
		t.Errorf("expected %s, got %s", Type, link.Type())
	}
}

func TestRunType(t *testing.T) {
	link := New()
	if link.RunType() != RunType {
		t.Errorf("expected %s, got %s", RunType, link.RunType())
	}
}

func TestExport(t *testing.T) {
	link := New()
	if link.export != defaultExport {
		t.Errorf("expected %t, got %t", defaultExport, link.export)
	}

	WithExport(true)(link)
	if !link.export {
		t.Errorf("expected %t, got %t", true, link.export)
	}

	if link.Export() != true {
		t.Errorf("expected %t, got %t", true, link.Export())
	}
}

func TestUnmarshalJSON(t *testing.T) {
	link := New()
	if err := link.UnmarshalJSON([]byte(testLinkJSON)); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestUnmarshalBadJSON(t *testing.T) {
	link := New()
	if err := link.UnmarshalJSON([]byte("}")); err == nil {
		t.Error("Expected error")
	}
}

func TestMarshalJSON(t *testing.T) {
	link := New()
	if err := link.UnmarshalJSON([]byte(testLinkJSON)); err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	_, err := link.MarshalJSON()
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestAttest(t *testing.T) {
	// Setup Env
	e := attestors.NewTestEnvironmentAttestor()
	e.Data().Variables = map[string]string{
		"COLORFGBG": "7;0",
		"COLORTERM": "truecolor",
	}

	// Setup Materials
	m := attestors.NewTestMaterialAttestor()
	materials := make(map[string]cryptoutil.DigestSet)
	materials["test2"] = cryptoutil.DigestSet{{Hash: crypto.SHA256, GitOID: false}: "a53d0741798b287c6dd7afa64aee473f305e65d3f49463bb9d7408ec3b12bf5f"}
	materials["test1"] = cryptoutil.DigestSet{{Hash: crypto.SHA256, GitOID: false}: "a53d0741798b287c6dd7afa64aee473f305e65d3f49463bb9d7408ec3b12bf5f"}
	m.SetMaterials(materials)

	// Setup CommandRun
	c := attestors.NewTestCommandRunAttestor()
	c.Data().Cmd = []string{"touch", "test.txt"}

	// Setup Products
	p := attestors.NewTestProductAttestor()

	l := New()

	ctx, err := attestation.NewContext("test", []attestation.Attestor{e, m, c, p, l})
	if err != nil {
		t.Errorf("error creating attestation context: %s", err)
	}

	err = ctx.RunAttestors()
	if err != nil {
		t.Errorf("error attesting: %s", err.Error())
	}

	var linkJson []byte
	if linkJson, err = json.MarshalIndent(l, "", "  "); err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	testJson := []byte(testLinkJSON)
	if !bytes.Equal(linkJson, testJson) {
		testJson := []byte(testLinkJSONAlternative)
		if !bytes.Equal(linkJson, testJson) {
			t.Errorf("expected \n%s\n, got \n%s\n", testJson, linkJson)
		}
	}
}

func TestSubjects(t *testing.T) {
	link := setupLink(t)

	subjects := link.Subjects()

	if len(subjects) != 1 {
		t.Errorf("expected 1 subjects, got %d", len(subjects))
	}

	digests := subjects["file:test.txt"]
	nameMap, err := digests.ToNameMap()
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if len(nameMap) != 1 {
		t.Errorf("expected 1 digest found, got %d", len(nameMap))
	}

	if nameMap["sha256"] != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("expected e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855, got %s", nameMap["sha256"])
	}
}

func setupLink(t *testing.T) *Link {
	link := New()
	if err := link.UnmarshalJSON([]byte(testLinkJSON)); err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	link.products = make(map[string]attestation.Product)
	digestsByName := make(map[string]string)
	digestsByName["sha256"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	digestSet, err := cryptoutil.NewDigestSet(digestsByName)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	link.products["test.txt"] = attestation.Product{
		MimeType: "text/plain",
		Digest:   digestSet,
	}

	return link
}

func TestRegistration(t *testing.T) {
	registrations := attestation.RegistrationEntries()

	var found bool
	for _, registration := range registrations {
		if registration.Name == Name {
			found = true
		}
	}

	if !found {
		t.Errorf("expected %s to be registered", Name)
	}
}

const testLinkJSON = `{
  "name": "test",
  "command": [
    "touch",
    "test.txt"
  ],
  "materials": [
    {
      "name": "test2",
      "digest": {
        "sha256": "a53d0741798b287c6dd7afa64aee473f305e65d3f49463bb9d7408ec3b12bf5f"
      }
    },
    {
      "name": "test1",
      "digest": {
        "sha256": "a53d0741798b287c6dd7afa64aee473f305e65d3f49463bb9d7408ec3b12bf5f"
      }
    }
  ],
  "environment": {
    "COLORFGBG": "7;0",
    "COLORTERM": "truecolor"
  }
}`

const testLinkJSONAlternative = `{
  "name": "test",
  "command": [
    "touch",
    "test.txt"
  ],
  "materials": [
    {
      "name": "test1",
      "digest": {
        "sha256": "a53d0741798b287c6dd7afa64aee473f305e65d3f49463bb9d7408ec3b12bf5f"
      }
    },
    {
      "name": "test2",
      "digest": {
        "sha256": "a53d0741798b287c6dd7afa64aee473f305e65d3f49463bb9d7408ec3b12bf5f"
      }
    }
  ],
  "environment": {
    "COLORFGBG": "7;0",
    "COLORTERM": "truecolor"
  }
}`
