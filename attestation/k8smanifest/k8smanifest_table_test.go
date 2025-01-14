package k8smanifest_test

import (
	"crypto"
	"os"
	"path/filepath"
	"testing"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/k8smanifest"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/require"
)

// producter is the same from before, for convenience
type producter struct {
	name     string
	runType  attestation.RunType
	products map[string]attestation.Product
}

func (p producter) Name() string                                 { return p.name }
func (p producter) Type() string                                 { return p.name }
func (p producter) RunType() attestation.RunType                 { return p.runType }
func (p producter) Schema() *jsonschema.Schema                   { return jsonschema.Reflect(&p) }
func (p producter) Attest(*attestation.AttestationContext) error { return nil }
func (p producter) Products() map[string]attestation.Product     { return p.products }

// hasPropertyKeyInAttestor is the same helper from your existing test code.
func hasPropertyKeyInAttestor(s *jsonschema.Schema, key string) bool {
	attestorSchema, ok := s.Definitions["Attestor"]
	if !ok || attestorSchema == nil || attestorSchema.Properties == nil {
		return false
	}
	for pair := attestorSchema.Properties.Oldest(); pair != nil; pair = pair.Next() {
		if pair.Key == key {
			return true
		}
	}
	return false
}

func TestK8smanifest_TableDriven(t *testing.T) {
	// We'll define a few YAML strings as “fixtures” for convenience:
	singleDocYAML := `apiVersion: v1
kind: ConfigMap
metadata:
  name: single-doc
data:
  key: "value"`

	multiDocYAML := `apiVersion: v1
kind: ConfigMap
metadata:
  name: config-one
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: deploy-two
`

	ephemeralYAML := `apiVersion: v1
kind: Pod
metadata:
  name: ephemeral-pod
  uid: 999
  resourceVersion: "111"
  annotations:
    witness.dev/content-hash: "somehash"
status:
  ready: false
`

	// Define a table of sub-tests
	cases := []struct {
		name string
		// Setup for the test
		serverSideDryRun bool
		kubeconfigPath   string
		ignoreFields     []string
		// We'll create a product set (map) or nil
		productFiles map[string]string // filename => YAML content
		// The expected outcome
		expectDocsCount     int
		expectSubjectsCount int
		expectSkipNoError   bool // if we skip due to no products or no .yaml
		checkIgnoreFields   bool // whether we want to check "IgnoreFields" in the schema
	}{
		{
			name:                "NoProducts_Skip",
			productFiles:        nil,
			expectDocsCount:     0,
			expectSubjectsCount: 0,
			expectSkipNoError:   true,
		},
		{
			name: "NoYAML_Skip",
			productFiles: map[string]string{
				"readme.txt": "hello world", // not a .yaml
			},
			expectDocsCount:     0,
			expectSubjectsCount: 0,
			expectSkipNoError:   true,
		},
		{
			name: "SingleDoc",
			productFiles: map[string]string{
				"config.yaml": singleDocYAML,
			},
			expectDocsCount:     1,
			expectSubjectsCount: 1,
		},
		{
			name: "MultiDoc",
			productFiles: map[string]string{
				"multi.yaml": multiDocYAML,
			},
			expectDocsCount:     2,
			expectSubjectsCount: 2,
		},
		{
			name: "Ephemeral",
			productFiles: map[string]string{
				"ephemeral.yaml": ephemeralYAML,
			},
			expectDocsCount:     1,
			expectSubjectsCount: 1,
		},
		{
			name:             "ServerSideDryRun",
			serverSideDryRun: true,
			productFiles: map[string]string{
				"config.yaml": singleDocYAML,
			},
			expectDocsCount:     1,
			expectSubjectsCount: 1,
		},
		{
			name:           "WithKubeconfigPath",
			kubeconfigPath: "/tmp/fakeconfig",
			productFiles: map[string]string{
				"config.yaml": singleDocYAML,
			},
			expectDocsCount:     1,
			expectSubjectsCount: 1,
		},
		{
			name:         "WithExtraIgnoreFields",
			ignoreFields: []string{"metadata.labels.myorg", "metadata.annotations.somethingRandom"},
			productFiles: map[string]string{
				"single.yaml": singleDocYAML,
			},
			expectDocsCount:     1,
			expectSubjectsCount: 1,
			checkIgnoreFields:   true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// 1) Create a temp dir
			tmpDir := t.TempDir()

			// 2) If we have product files, write them to tmpDir
			var products map[string]attestation.Product
			if c.productFiles != nil {
				products = make(map[string]attestation.Product, len(c.productFiles))
				for fname, content := range c.productFiles {
					full := filepath.Join(tmpDir, fname)
					require.NoError(t, os.WriteFile(full, []byte(content), 0o600))
					// compute digest
					dig, err := cryptoutil.CalculateDigestSetFromFile(full, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
					require.NoError(t, err)
					// record in the products map
					products[fname] = attestation.Product{
						MimeType: "text/yaml",
						Digest:   dig,
					}
				}
			}

			// 3) Create the producter
			prod := producter{
				name:     "test-products",
				runType:  attestation.ProductRunType,
				products: products,
			}

			// 4) Create the k8smanifest attestor
			km := k8smanifest.New()

			// Apply our scenario config
			if c.serverSideDryRun {
				k8smanifest.WithServerSideDryRun(true)(km)
			}
			if c.kubeconfigPath != "" {
				k8smanifest.WithKubeconfigPath(c.kubeconfigPath)(km)
			}
			if len(c.ignoreFields) > 0 {
				k8smanifest.WithExtraIgnoreFields(c.ignoreFields...)(km)
			}

			// 5) Create an AttestationContext
			attCtx, err := attestation.NewContext(
				"table-test",
				[]attestation.Attestor{prod, km},
				attestation.WithWorkingDir(tmpDir),
			)
			require.NoError(t, err)

			// 6) Run
			err = attCtx.RunAttestors()

			// 7) If we expect skipNoError, then err should be nil
			if c.expectSkipNoError {
				require.NoError(t, err, "attestor should skip gracefully, not fail")
			} else {
				// We do not forcibly require an error, we just check that the attestor didn't skip
				// e.g. if there's no skip scenario we might do require.NoError(t, err)
				// or check err for nil
				require.NoError(t, err, "attestor should succeed and not return an error")
			}

			// 8) Check doc count and subject count
			require.Len(t, km.RecordedDocs, c.expectDocsCount, "RecordedDocs mismatch")
			subs := km.Subjects()
			require.Len(t, subs, c.expectSubjectsCount, "Subjects mismatch")

			// 9) If we want to check "IgnoreFields" is in the schema
			//    we look in the "Attestor" sub-schema since RootRef is true.
			if c.checkIgnoreFields {
				sch := km.Schema()
				require.True(t, hasPropertyKeyInAttestor(sch, "IgnoreFields"),
					"the schema should have 'IgnoreFields' in Attestor.Properties")
			}
		})
	}
}
