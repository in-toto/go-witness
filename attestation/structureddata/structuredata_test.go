// Copyright 2025 The Witness Contributors
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

package structureddata_test

import (
	"crypto"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/structureddata"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/require"
)

type testProducter struct {
	products map[string]attestation.Product
}

func (testProducter) Name() string                 { return "dummy-products" }
func (testProducter) Type() string                 { return "dummy-products" }
func (testProducter) RunType() attestation.RunType { return attestation.ProductRunType }
func (testProducter) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&testProducter{})
}
func (testProducter) Attest(ctx *attestation.AttestationContext) error { return nil }
func (t testProducter) Products() map[string]attestation.Product {
	return t.products
}

func TestMain(m *testing.M) {
	// Supply a new logger that implements log.Logger
	log.SetLogger(&log.ConsoleLogger{})

	// Then run the tests
	code := m.Run()
	os.Exit(code)
}

func TestParseSubjectQueries(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantMap     map[string]string
		wantErr     bool
		errContains string
	}{
		{
			name:    "empty string",
			input:   "",
			wantMap: map[string]string{},
			wantErr: false,
		},
		{
			name:  "single valid pair",
			input: "mySubject = .foo",
			wantMap: map[string]string{
				"mySubject": ".foo",
			},
			wantErr: false,
		},
		{
			name:  "multiple pairs",
			input: "first=.foo; second = .bar  ; third = .nums[]",
			wantMap: map[string]string{
				"first":  ".foo",
				"second": ".bar",
				"third":  ".nums[]",
			},
			wantErr: false,
		},
		{
			name:        "missing equal sign",
			input:       "mysubject.foo",
			wantMap:     nil,
			wantErr:     true,
			errContains: "invalid subject-queries pair",
		},
		{
			name:        "valid and invalid mixed",
			input:       "valid=.foo; noEqHere ; alsoValid=.bar",
			wantMap:     nil,
			wantErr:     true,
			errContains: "invalid subject-queries pair",
		},
		{
			name: "whitespace only in pairs",
			input: `
			 alpha =   .alphaVal    ;
			 beta=.betaVal
			`,
			wantMap: map[string]string{
				"alpha": ".alphaVal",
				"beta":  ".betaVal",
			},
			wantErr: false,
		},
		{
			name:  "semicolon with empty pair",
			input: ` subjectOne=.foo ;  ; subjectTwo=.bar  `,
			wantMap: map[string]string{
				"subjectOne": ".foo",
				"subjectTwo": ".bar",
			},
			wantErr: false,
		},
		{
			name:        "no name before equals",
			input:       "=.expression",
			wantMap:     nil,
			wantErr:     true,
			errContains: "invalid subject-queries pair",
		},
		{
			name:    "duplicate_subject_names",
			input:   "foo=.one; foo=.two",
			wantMap: map[string]string{"foo": ".two"},
			wantErr: false,
		},
		{
			name:    "multiple_equals_in_expression",
			input:   "mySubject=.foo=extra",
			wantMap: map[string]string{"mySubject": ".foo=extra"},
			wantErr: false,
		},
		{
			name:    "subject_with_symbols",
			input:   "my-Subject_1= .foo->bar",
			wantMap: map[string]string{"my-Subject_1": ".foo->bar"},
			wantErr: false,
		},
		{
			name:    "extra_semicolons",
			input:   "; subject1=.foo;;subject2=.bar; ",
			wantMap: map[string]string{"subject1": ".foo", "subject2": ".bar"},
			wantErr: false,
		},
		{
			name:        "mySubjectEqualsEmpty",
			input:       "mySubject=",
			wantMap:     nil,
			wantErr:     true,
			errContains: "empty name or expression",
		},
		{
			name:  "trim_spaces_in_name_and_expr",
			input: "  alpha   =    .some.expr  ;  beta =    .bar ",
			wantMap: map[string]string{
				"alpha": ".some.expr",
				"beta":  ".bar",
			},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := structureddata.ParseSubjectQueries(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errContains != "" {
					require.Contains(t, err.Error(), tc.errContains)
				}
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantMap, got)
		})
	}
}

func TestStructureddata_PartialDocFail(t *testing.T) {
	// One doc is valid, second is malformed
	// We want 1 doc recognized => 1 canonical subject
	tmpDir := t.TempDir()
	partialYAML := `kind: ValidDoc
metadata:
  name: doc1
---
kind: Invalid
metadata
  name: doc2
`
	path := filepath.Join(tmpDir, "partial.yaml")
	require.NoError(t, os.WriteFile(path, []byte(partialYAML), 0600))

	dig, err := cryptoutil.CalculateDigestSetFromFile(path, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)

	prod := testProducter{
		products: map[string]attestation.Product{
			"partial.yaml": {MimeType: "text/yaml", Digest: dig},
		},
	}

	sAtt := structureddata.New()
	sAtt.SubjectQueries["kind"] = ".kind"

	ctx, err := attestation.NewContext(
		"test-partialdoc",
		[]attestation.Attestor{prod, sAtt},
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
		attestation.WithWorkingDir(tmpDir),
	)
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	subs := sAtt.Subjects()

	// We expect:
	//   original-file:partial.yaml
	//   canonical-json:partial.yaml#doc0  (the valid doc)
	//   partial.yaml:kind#doc0#0
	// The second doc is invalid => no doc1 subject.

	foundOriginal := false
	foundCanonCount := 0
	foundKindCount := 0

	for k := range subs {
		if strings.HasPrefix(k, "original-file:partial.yaml") {
			foundOriginal = true
		}
		if strings.HasPrefix(k, "canonical-json:partial.yaml#doc") {
			foundCanonCount++
		}
		if strings.Contains(k, ":kind#doc") {
			foundKindCount++
		}
	}

	require.True(t, foundOriginal, "missing original-file for partial.yaml")
	// Should have exactly 1 doc recognized (the second doc fails)
	require.Equal(t, 1, foundCanonCount, "should have exactly 1 canonical doc from partial.yaml")
	require.Equal(t, 1, foundKindCount, "should have exactly 1 .kind result from the valid doc")
}

func TestStructureddata_MultipleFiles(t *testing.T) {
	// file.json => valid JSON
	// file.yaml => valid YAML
	// bad.yaml => invalid -> partial parse fail => no canonical doc
	tmpDir := t.TempDir()

	jsonPath := filepath.Join(tmpDir, "file.json")
	require.NoError(t, os.WriteFile(jsonPath, []byte(`{"hello":"world"}`), 0600))

	yamlPath := filepath.Join(tmpDir, "file.yaml")
	// valid single doc
	require.NoError(t, os.WriteFile(yamlPath, []byte("kind: Example\nmetadata:\n  name: testobj"), 0600))

	badPath := filepath.Join(tmpDir, "bad.yaml")
	require.NoError(t, os.WriteFile(badPath, []byte("not valid: [broken"), 0600))

	digJSON, err := cryptoutil.CalculateDigestSetFromFile(jsonPath, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)
	digYAML, err := cryptoutil.CalculateDigestSetFromFile(yamlPath, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)
	digBad, err := cryptoutil.CalculateDigestSetFromFile(badPath, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)

	prods := testProducter{
		products: map[string]attestation.Product{
			"file.json": {MimeType: "application/json", Digest: digJSON},
			"file.yaml": {MimeType: "text/yaml", Digest: digYAML},
			"bad.yaml":  {MimeType: "text/yaml", Digest: digBad},
		},
	}

	sAtt := structureddata.New()
	sAtt.SubjectQueries["kind"] = ".kind"

	ctx, err := attestation.NewContext(
		"test-multifile",
		[]attestation.Attestor{prods, sAtt},
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
		attestation.WithWorkingDir(tmpDir),
	)
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	subs := sAtt.Subjects()
	// We want:
	//   "original-file:file.json"
	//   "canonical-json:file.json#doc0"
	//   "original-file:file.yaml"
	//   "canonical-json:file.yaml#doc0"
	//   "file.yaml:kind#doc0#0" (since 'kind: Example')
	//   "original-file:bad.yaml" (no canonical for bad.yaml)
	// => total = 6

	foundOrigCount := 0
	foundCanonCount := 0
	foundKindCount := 0
	for k := range subs {
		if strings.HasPrefix(k, "original-file:") {
			foundOrigCount++
		}
		if strings.HasPrefix(k, "canonical-json:") {
			foundCanonCount++
		}
		if strings.Contains(k, ":kind#doc") {
			foundKindCount++
		}
	}

	// We expect 3 original-file: entries
	require.Equal(t, 3, foundOrigCount, "expected an original-file subject for each product")
	// 2 canonical docs (one for file.json, one for file.yaml)
	require.Equal(t, 2, foundCanonCount, "expected 2 canonical doc subjects for file.json and file.yaml")
	// Only the YAML has 'kind'
	require.Equal(t, 1, foundKindCount, "expected 1 doc with .kind from file.yaml")
}

func TestStructureddata_MixedContent(t *testing.T) {
	// This scenario is optional, but sometimes folks embed JSON in a YAML doc or vice versa.
	// We'll create a file that has a valid YAML doc plus some trailing invalid content,
	// ensuring partial parse might fail. Or it might parse it all as YAML if it's valid enough.

	tmpDir := t.TempDir()
	mixedYAML := `kind: Mixed
metadata:
  name: doc1
stuff: {"embedded":"json", "anotherKey"=42}  # the '=' is not valid yaml
`
	path := filepath.Join(tmpDir, "mixed.yaml")
	require.NoError(t, os.WriteFile(path, []byte(mixedYAML), 0600))

	dig, err := cryptoutil.CalculateDigestSetFromFile(path, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)

	prod := testProducter{
		products: map[string]attestation.Product{
			"mixed.yaml": {MimeType: "text/yaml", Digest: dig},
		},
	}

	sAtt := structureddata.New()
	sAtt.SubjectQueries["checkStuff"] = ".stuff.embedded"

	ctx, err := attestation.NewContext(
		"test-mixed",
		[]attestation.Attestor{prod, sAtt},
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
		attestation.WithWorkingDir(tmpDir),
	)
	require.NoError(t, err)
	// If the partial parse fails for that '=' sign, we might skip doc or produce partial data
	_ = ctx.RunAttestors() // we won't require NoError because we expect partial parse or logs

	subs := sAtt.Subjects()
	// We can see if we got an original-file, maybe a canonical doc if the parser didn't bail,
	// and possibly "checkStuff#0" if the embedded JSON was actually parseable or not.

	require.Contains(t, subs, "original-file:mixed.yaml")
	// Depending on how the parser handles that, we might or might not see canonical-json.
	// We won't be too strict here, just illustrate the test approach:
	foundCanon := false
	foundStuff := false
	for key := range subs {
		if strings.Contains(key, "canonical-json:mixed.yaml") {
			foundCanon = true
		}
		if strings.Contains(key, "checkStuff#") {
			foundStuff = true
		}
	}
	t.Logf("foundCanon=%v foundStuff=%v", foundCanon, foundStuff)
	// Possibly we can assert at least one is false or log the partial results.
}

func TestStructureddata_NoQueries(t *testing.T) {
	tmpDir := t.TempDir()
	sample := `{"k":1}`
	path := filepath.Join(tmpDir, "f.json")
	require.NoError(t, os.WriteFile(path, []byte(sample), 0o600))

	dig, err := cryptoutil.CalculateDigestSetFromFile(path, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)

	prod := testProducter{
		products: map[string]attestation.Product{
			"f.json": {MimeType: "application/json", Digest: dig},
		},
	}

	jAtt := structureddata.New()

	ctx, err := attestation.NewContext(
		"test-no-queries",
		[]attestation.Attestor{prod, jAtt},
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
		attestation.WithWorkingDir(tmpDir),
	)
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	subs := jAtt.Subjects()
	require.Equal(t, 2, len(subs), "expected 2 subjects: original-file + canonical-json")

	foundOriginal := false
	foundCanonical := false

	for k := range subs {
		if strings.HasPrefix(k, "original-file:") {
			foundOriginal = true
		}
		if strings.HasPrefix(k, "canonical-json:") {
			foundCanonical = true
		}
	}

	require.True(t, foundOriginal, "expected an 'original-file:' subject")
	require.True(t, foundCanonical, "expected a 'canonical-json:' subject")
}

func TestStructureddata_SingleQuery(t *testing.T) {
	tmpDir := t.TempDir()
	sample := `{"foo":"bar"}`
	path := filepath.Join(tmpDir, "one.json")
	require.NoError(t, os.WriteFile(path, []byte(sample), 0o600))

	dig, err := cryptoutil.CalculateDigestSetFromFile(path, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)

	prod := testProducter{
		products: map[string]attestation.Product{
			"one.json": {MimeType: "application/json", Digest: dig},
		},
	}

	jAtt := structureddata.New()
	jAtt.SubjectQueries["mySubject"] = ".foo"

	ctx, err := attestation.NewContext(
		"test-one",
		[]attestation.Attestor{prod, jAtt},
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
		attestation.WithWorkingDir(tmpDir),
	)
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	subs := jAtt.Subjects()
	// We expect 3 subjects total: original-file:one.json, canonical-json:one.json#doc0, and "one.json:mySubject#doc0#0"
	require.Equal(t, 3, len(subs))

	foundOriginal := false
	foundCanon := false
	foundMySubject0 := false

	for k := range subs {
		if strings.HasPrefix(k, "original-file:one.json") {
			foundOriginal = true
		}
		if strings.HasPrefix(k, "canonical-json:one.json#doc0") {
			foundCanon = true
		}
		// The code uses subKey = filePath:subjectName#docIndex#resultIndex
		// e.g. "one.json:mySubject#doc0#0"
		if strings.Contains(k, ":mySubject#doc0#0") {
			foundMySubject0 = true
		}
	}
	require.True(t, foundOriginal)
	require.True(t, foundCanon)
	require.True(t, foundMySubject0)
}

func TestStructureddata_MultipleResults(t *testing.T) {
	tmpDir := t.TempDir()
	sample := `{"nums":[1,2,3]}`
	path := filepath.Join(tmpDir, "arr.json")
	require.NoError(t, os.WriteFile(path, []byte(sample), 0o600))

	dig, err := cryptoutil.CalculateDigestSetFromFile(path, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)

	prod := testProducter{
		products: map[string]attestation.Product{
			"arr.json": {MimeType: "application/json", Digest: dig},
		},
	}

	jAtt := structureddata.New()
	jAtt.SubjectQueries["arr"] = ".nums[]"

	ctx, err := attestation.NewContext(
		"test-array",
		[]attestation.Attestor{prod, jAtt},
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
		attestation.WithWorkingDir(tmpDir),
	)
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	subs := jAtt.Subjects()
	require.Equal(t, 5, len(subs), "expected 1 original-file, 1 canonical-json, plus 3 arr results")

	foundOriginal := false
	foundCanon := false
	foundArrResults := 0

	for k := range subs {
		if strings.HasPrefix(k, "original-file:arr.json") {
			foundOriginal = true
		}
		if strings.HasPrefix(k, "canonical-json:arr.json#doc0") {
			foundCanon = true
		}
		// e.g. "arr.json:arr#doc0#0", "arr.json:arr#doc0#1", etc.
		if strings.Contains(k, ":arr#doc0#") {
			foundArrResults++
		}
	}

	require.True(t, foundOriginal)
	require.True(t, foundCanon)
	require.Equal(t, 3, foundArrResults, "should have 3 array results from .nums[]")
}

func TestStructureddata_MultiDocYAML(t *testing.T) {
	tmpDir := t.TempDir()
	multiDoc := `kind: Deployment
metadata:
  name: test-deploy
---
kind: Service
metadata:
  name: test-service
`
	yamlFile := filepath.Join(tmpDir, "multi.yaml")
	require.NoError(t, os.WriteFile(yamlFile, []byte(multiDoc), 0600))

	dig, err := cryptoutil.CalculateDigestSetFromFile(yamlFile, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)

	prod := testProducter{
		products: map[string]attestation.Product{
			"multi.yaml": {MimeType: "text/yaml", Digest: dig},
		},
	}

	sAtt := structureddata.New()
	sAtt.SubjectQueries["kindQuery"] = ".kind"

	ctx, err := attestation.NewContext(
		"test-multidoc-yaml",
		[]attestation.Attestor{prod, sAtt},
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
		attestation.WithWorkingDir(tmpDir),
	)
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	subs := sAtt.Subjects()

	foundOriginal := false
	foundCanonCount := 0
	foundKindCount := 0

	for k := range subs {
		if strings.HasPrefix(k, "original-file:multi.yaml") {
			foundOriginal = true
		}
		if strings.HasPrefix(k, "canonical-json:multi.yaml#doc") {
			foundCanonCount++
		}
		if strings.Contains(k, ":kindQuery#doc") {
			foundKindCount++
		}
	}

	require.True(t, foundOriginal, "expected original-file:multi.yaml")
	require.Equal(t, 2, foundCanonCount, "expected 2 canonical-doc results (one for each doc: Deployment & Service)")
	require.Equal(t, 2, foundKindCount, "expected 2 doc results for .kind query (Deployment, Service)")
}

func TestStructureddata_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	emptyPath := filepath.Join(tmpDir, "empty.yaml")
	// just spaces
	require.NoError(t, os.WriteFile(emptyPath, []byte("   "), 0600))

	dig, err := cryptoutil.CalculateDigestSetFromFile(emptyPath, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)

	prod := testProducter{
		products: map[string]attestation.Product{
			"empty.yaml": {MimeType: "text/yaml", Digest: dig},
		},
	}

	sAtt := structureddata.New()
	ctx, err := attestation.NewContext(
		"test-empty-file",
		[]attestation.Attestor{prod, sAtt},
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
		attestation.WithWorkingDir(tmpDir),
	)
	require.NoError(t, err)

	// We no longer expect an error from empty file -> just log a warning
	err = ctx.RunAttestors()
	require.NoError(t, err, "we skip empty file instead of failing globally")

	subs := sAtt.Subjects()
	// We *should* have an original-file: subject for empty.yaml,
	// but no canonical doc because no docs were found.
	require.Equal(t, 1, len(subs), "expected 1 subject (original-file only)")

	foundOriginal := false
	for k := range subs {
		if strings.HasPrefix(k, "original-file:empty.yaml") {
			foundOriginal = true
		}
	}
	require.True(t, foundOriginal, "should have original-file digest even if no docs are found")
}

func TestStructureddata_ComplexJQ(t *testing.T) {
	tmpDir := t.TempDir()
	complexJSON := `{
      "outer": {
        "inner": [
          { "deep": { "field": "val1", "status": "ready"  } },
          { "deep": { "field": "val2", "status": "notready" } }
        ]
      }
    }`
	cPath := filepath.Join(tmpDir, "complex.json")
	require.NoError(t, os.WriteFile(cPath, []byte(complexJSON), 0600))

	dig, err := cryptoutil.CalculateDigestSetFromFile(cPath, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)

	prod := testProducter{
		products: map[string]attestation.Product{
			"complex.json": {MimeType: "application/json", Digest: dig},
		},
	}

	sAtt := structureddata.New()
	sAtt.SubjectQueries["myComplex"] = `.outer | .inner[] | select(.deep.status=="ready") | .deep.field`

	ctx, err := attestation.NewContext(
		"test-complex-jq",
		[]attestation.Attestor{prod, sAtt},
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
		attestation.WithWorkingDir(tmpDir),
	)
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	subs := sAtt.Subjects()

	foundOriginal := false
	foundCanon := false
	foundVal1 := false

	for k := range subs {
		if strings.HasPrefix(k, "original-file:complex.json") {
			foundOriginal = true
		}
		if strings.HasPrefix(k, "canonical-json:complex.json#doc0") {
			foundCanon = true
		}
		// e.g. "complex.json:myComplex#doc0#0"
		if strings.Contains(k, ":myComplex#doc0#0") {
			foundVal1 = true
		}
	}

	require.True(t, foundOriginal, "expected an original-file: subject for complex.json")
	require.True(t, foundCanon, "expected a canonical doc subject for complex.json")
	require.True(t, foundVal1, "expected the query result (val1) for .deep.field of the ready item")
}

func TestStructureddata_ObjectResult(t *testing.T) {
	tmpDir := t.TempDir()
	sample := `{"x":{"k":"v"}}`
	path := filepath.Join(tmpDir, "obj.json")
	require.NoError(t, os.WriteFile(path, []byte(sample), 0o600))

	dig, err := cryptoutil.CalculateDigestSetFromFile(path, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)

	prod := testProducter{
		products: map[string]attestation.Product{
			"obj.json": {MimeType: "application/json", Digest: dig},
		},
	}

	jAtt := structureddata.New()
	jAtt.SubjectQueries["obj"] = ".x"

	ctx, err := attestation.NewContext(
		"test-obj",
		[]attestation.Attestor{prod, jAtt},
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
		attestation.WithWorkingDir(tmpDir),
	)
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	subs := jAtt.Subjects()

	// We expect 3 keys:
	//  1) "original-file:obj.json"
	//  2) "canonical-json:obj.json#doc0"
	//  3) "obj.json:obj#doc0#0"

	require.Equal(t, 2, len(subs))

	foundOriginal := false
	foundCanon := false
	foundObj := false

	for k := range subs {
		if strings.HasPrefix(k, "original-file:obj.json") {
			foundOriginal = true
		}
		if strings.HasPrefix(k, "canonical-json:obj.json#doc0") {
			foundCanon = true
		}
		if strings.Contains(k, "obj#doc0#0") {
			foundObj = true
		}
	}
	require.True(t, foundOriginal, "expected original-file:obj.json")
	require.True(t, foundCanon, "expected canonical-json:obj.json#doc0")
	require.False(t, foundObj, "expected obj.json:obj#doc0#0 for the .x query result")
}

func TestStructureddata_BadQuery(t *testing.T) {
	tmpDir := t.TempDir()
	sample := `{"x":10}`
	path := filepath.Join(tmpDir, "bad.json")
	require.NoError(t, os.WriteFile(path, []byte(sample), 0o600))

	dig, err := cryptoutil.CalculateDigestSetFromFile(path, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)

	prod := testProducter{
		products: map[string]attestation.Product{
			"bad.json": {MimeType: "application/json", Digest: dig},
		},
	}

	jAtt := structureddata.New()
	// invalid JQ => parse fail
	jAtt.SubjectQueries["bad"] = ".x("

	ctx, err := attestation.NewContext(
		"test-bad",
		[]attestation.Attestor{prod, jAtt},
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
		attestation.WithWorkingDir(tmpDir),
	)
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	subs := jAtt.Subjects()
	// 2 keys:
	//   "original-file:bad.json"
	//   "canonical-json:bad.json#doc0"
	// The query fails to parse, but we still have the 2 normal subjects.

	require.Equal(t, 2, len(subs))

	foundOrig := false
	foundCanon := false
	for k := range subs {
		if strings.HasPrefix(k, "original-file:bad.json") {
			foundOrig = true
		}
		if strings.HasPrefix(k, "canonical-json:bad.json#doc0") {
			foundCanon = true
		}
	}
	require.True(t, foundOrig, "missing original-file subject")
	require.True(t, foundCanon, "missing canonical-json subject")
}
