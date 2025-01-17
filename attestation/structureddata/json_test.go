package structureddata_test

import (
	"crypto"
	"os"
	"path/filepath"
	"testing"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/structureddata"
	"github.com/in-toto/go-witness/cryptoutil"
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

func Teststructureddata_NoQueries(t *testing.T) {
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
	require.Len(t, subs, 2)
	require.Contains(t, subs, "original-file")
	require.Contains(t, subs, "canonical-json")
}

func Teststructureddata_SingleQuery(t *testing.T) {
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
	require.Len(t, subs, 3)
	require.Contains(t, subs, "original-file")
	require.Contains(t, subs, "canonical-json")
	require.Contains(t, subs, "mySubject#0")
}

func Teststructureddata_MultipleResults(t *testing.T) {
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
	require.Len(t, subs, 5)
	require.Contains(t, subs, "original-file")
	require.Contains(t, subs, "canonical-json")
	require.Contains(t, subs, "arr#0")
	require.Contains(t, subs, "arr#1")
	require.Contains(t, subs, "arr#2")
}

func Teststructureddata_ObjectResult(t *testing.T) {
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
	require.Len(t, subs, 3)
	require.Contains(t, subs, "original-file")
	require.Contains(t, subs, "canonical-json")
	require.Contains(t, subs, "obj#0")
}

func Teststructureddata_BadQuery(t *testing.T) {
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
	require.Len(t, subs, 2)
	require.Contains(t, subs, "original-file")
	require.Contains(t, subs, "canonical-json")
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
