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
	"bytes"
	"crypto"
	"encoding/json"
	"testing"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/internal/attestors"
	"google.golang.org/protobuf/types/known/timestamppb"
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
	if err := provenance.UnmarshalJSON([]byte(testGHProvJSON)); err != nil {
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
	if err := provenance.UnmarshalJSON([]byte(testGHProvJSON)); err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	_, err := provenance.MarshalJSON()
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
}

func TestAttest(t *testing.T) {
	// Setup Env
	e := attestors.NewTestEnvironmentAttestor()
	e.Data().Variables = map[string]string{
		"SHELL":        "/bin/zsh",
		"TERM":         "xterm-256color",
		"TERM_PROGRAM": "iTerm.app",
	}

	// Setup Git
	g := attestors.NewTestGitAttestor()
	g.Data().CommitDigest = cryptoutil.DigestSet{
		{Hash: crypto.SHA1, GitOID: false}: "abc123",
	}
	g.Data().Remotes = []string{"git@github.com:in-toto/witness.git"}

	// Setup GitHub
	gh := attestors.NewTestGitHubAttestor()
	gh.Data().JWT.Claims["sha"] = "abc123"
	gh.Data().PipelineUrl = "https://github.com/testifysec/swf/actions/runs/7879307166"

	// Setup GitLab
	gl := attestors.NewTestGitLabAttestor()
	gl.Data().JWT.Claims["sha"] = "abc123"
	gl.Data().PipelineUrl = "https://github.com/testifysec/swf/actions/runs/7879307166"

	// Setup Materials
	m := attestors.NewTestMaterialAttestor()

	// Setup CommandRun
	c := attestors.NewTestCommandRunAttestor()
	c.Data().Cmd = []string{"touch", "test.txt"}

	// Setup Products
	p := attestors.NewTestProductAttestor()

	// Setup OCI
	o := attestors.NewTestOCIAttestor()

	var tests = []struct {
		name         string
		attestors    []attestation.Attestor
		expectedJson string
	}{
		{"github", []attestation.Attestor{e, g, gh, m, c, p, o}, testGHProvJSON},
		{"gitlab", []attestation.Attestor{e, g, gl, m, c, p, o}, testGLProvJSON},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Logf("Running test %s", test.name)
			s := New()

			ctx, err := attestation.NewContext("test", append(test.attestors, s))
			if err != nil {
				t.Errorf("error creating attestation context: %s", err)
			}

			err = ctx.RunAttestors()
			if err != nil {
				t.Errorf("error attesting: %s", err.Error())
			}

			// TODO: We don't have a way to mock out times on attestor runs
			// Set attestor times manually to match testProvenanceJSON
			s.PbProvenance.RunDetails.Metadata.StartedOn = &timestamppb.Timestamp{
				Seconds: 1711199861,
				Nanos:   560152000,
			}
			s.PbProvenance.RunDetails.Metadata.FinishedOn = &timestamppb.Timestamp{
				Seconds: 1711199861,
				Nanos:   560152000,
			}

			var prov []byte
			if prov, err = json.MarshalIndent(s, "", "  "); err != nil {
				t.Errorf("unexpected error: %s", err)
			}

			testJson := []byte(test.expectedJson)
			if !bytes.Equal(prov, testJson) {
				t.Errorf("expected \n%s\n, got \n%s\n", testJson, prov)
			}
		})
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
	if err := provenance.UnmarshalJSON([]byte(testGHProvJSON)); err != nil {
		t.Errorf("unexpected error: %s", err)
	}

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

const testGHProvJSON = `{
  "build_definition": {
    "build_type": "https://witness.dev/slsa-build@v0.1",
    "external_parameters": {
      "command": "touch test.txt"
    },
    "internal_parameters": {
      "env": {
        "SHELL": "/bin/zsh",
        "TERM": "xterm-256color",
        "TERM_PROGRAM": "iTerm.app"
      }
    },
    "resolved_dependencies": [
      {
        "name": "git@github.com:in-toto/witness.git",
        "digest": {
          "sha1": "abc123"
        }
      }
    ]
  },
  "run_details": {
    "builder": {
      "id": "https://witness.dev/witness-github-action-builder@v0.1"
    },
    "metadata": {
      "invocation_id": "https://github.com/testifysec/swf/actions/runs/7879307166",
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
}`

const testGLProvJSON = `{
  "build_definition": {
    "build_type": "https://witness.dev/slsa-build@v0.1",
    "external_parameters": {
      "command": "touch test.txt"
    },
    "internal_parameters": {
      "env": {
        "SHELL": "/bin/zsh",
        "TERM": "xterm-256color",
        "TERM_PROGRAM": "iTerm.app"
      }
    },
    "resolved_dependencies": [
      {
        "name": "git@github.com:in-toto/witness.git",
        "digest": {
          "sha1": "abc123"
        }
      }
    ]
  },
  "run_details": {
    "builder": {
      "id": "https://witness.dev/witness-gitlab-component-builder@v0.1"
    },
    "metadata": {
      "invocation_id": "https://github.com/testifysec/swf/actions/runs/7879307166",
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
}`
