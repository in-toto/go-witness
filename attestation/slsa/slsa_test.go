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

package slsa

import (
	"testing"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/internal/attestors"
)

func TestName(t *testing.T) {
	provenance := New()
	if provenance.Name() != Name {
		t.Errorf("expected %s, got %s", Name, provenance.Name())
	}
}

func TestType(t *testing.T) {
	provenance := New()
	if provenance.Type() != Type {
		t.Errorf("expected %s, got %s", Type, provenance.Type())
	}
}

func TestRunType(t *testing.T) {
	provenance := New()
	if provenance.RunType() != RunType {
		t.Errorf("expected %s, got %s", RunType, provenance.RunType())
	}
}

func TestExport(t *testing.T) {
	provenance := New()
	if provenance.export != defaultExport {
		t.Errorf("expected %t, got %t", defaultExport, provenance.export)
	}

	WithExport(true)(provenance)
	if !provenance.export {
		t.Errorf("expected %t, got %t", true, provenance.export)
	}

	if provenance.Export() != true {
		t.Errorf("expected %t, got %t", true, provenance.Export())
	}
}

func TestUnmarshalJSON(t *testing.T) {
	provenance := New()
	if err := provenance.UnmarshalJSON([]byte(testProvenanceJSON)); err != nil {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestUnmarshalBadJSON(t *testing.T) {
	provenance := New()
	if err := provenance.UnmarshalJSON([]byte("}")); err == nil {
		t.Error("Expected error")
	}
}

func TestMarshalJSON(t *testing.T) {
	provenance := New()
	if err := provenance.UnmarshalJSON([]byte(testProvenanceJSON)); err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	_, err := provenance.MarshalJSON()
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestAttest(t *testing.T) {
	g := &attestors.TestGitAttestor{}
	gh := &attestors.TestGitHubAttestor{}
	m := &attestors.TestMaterialAttestor{}
	c := &attestors.TestCommandRunAttestor{}
	p := &attestors.TestProductAttestor{}
	s := &Provenance{}

	ctx, err := attestation.NewContext([]attestation.Attestor{g, gh, m, c, p, s})
	if err != nil {
		t.Errorf("error creating attestation context: %s", err)
	}

	err = s.Attest(ctx)
	if err != nil {
		t.Errorf("error attesting: %s", err.Error())
	}
}

func TestSubjects(t *testing.T) {
	provenance := setupProvenance(t)

	subjects := provenance.Subjects()

	if len(subjects) != 1 {
		t.Errorf("expected 1 subjects, got %d", len(subjects))
	}

	digests := subjects["file:test.txt"]
	nameMap, err := digests.ToNameMap()
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}

	if len(nameMap) != 1 {
		t.Errorf("expected 1 digest found, got %d", len(nameMap))
	}

	if nameMap["sha256"] != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("expected e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855, got %s", nameMap["sha256"])
	}
}

func setupProvenance(t *testing.T) *Provenance {
	provenance := New()
	provenance.UnmarshalJSON([]byte(testProvenanceJSON))

	provenance.products = make(map[string]attestation.Product)
	digestsByName := make(map[string]string)
	digestsByName["sha256"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	digestSet, err := cryptoutil.NewDigestSet(digestsByName)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	provenance.products["test.txt"] = attestation.Product{
		MimeType: "text/plain",
		Digest:   digestSet,
	}

	return provenance
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

const testProvenanceJSON = `
{
	"type": "https://slsa.dev/provenance/v1.0",
	"attestation": {
	  "build_definition": {
		"build_type": "https://witness.dev/slsa-build@v0.1",
		"external_parameters": {
		  "command": "touch test.txt"
		},
		"internal_parameters": {
		  "env": {
			"COLORFGBG": "7;0",
			"COLORTERM": "truecolor",
			"COMMAND_MODE": "unix2003",
			"SHELL": "/bin/zsh",
			"SHLVL": "1",
			"TERM": "xterm-256color",
			"TERM_PROGRAM": "iTerm.app",
			"TERM_PROGRAM_VERSION": "3.4.23",
			"TERM_SESSION_ID": "w0t1p0:8939AC72-EB13-417F-9500-DD193C48127E",
			"TMPDIR": "/var/folders/qy/kpkfp9r140s08yk29dccpx540000gn/T/",
			"XPC_FLAGS": "0x0",
			"XPC_SERVICE_NAME": "0",
			"_": "/opt/homebrew/bin/go",
			"_P9K_SSH_TTY": "/dev/ttys005",
			"_P9K_TTY": "/dev/ttys005",
			"__CFBundleIdentifier": "com.googlecode.iterm2",
			"__CF_USER_TEXT_ENCODING": "0x1F5:0x0:0x0"
		  }
		},
		"resolved_dependencies": [
		  {
			"name": "git@github.com:in-toto/witness.git",
			"digest": {
			  "sha1": "51d0fa68cb991b7d3979df491e05fbf7765d6d1c"
			}
		  }
		]
	  },
	  "run_details": {
		"builder": {
		  "id": "https://witness.dev/witness-github-action@v0.1"
		},
		"metadata": {
		  "invocation_id": "gha-workflow-ref",
		  "started_on": {
			"seconds": 1711199861,
			"nanos": 560152000
		  },
		  "finished_on": {
			"seconds": 1711199861,
			"nanos": 560152000
		  }
		}
	  }
	}
}
`
