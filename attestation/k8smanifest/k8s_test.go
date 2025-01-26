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

package k8smanifest_test

import (
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

// hasPropertyKeyInAttestor is a helper to confirm a field is in the attestor's schema.
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
	singleDocYAML := `apiVersion: v1
kind: ConfigMap
metadata:
  name: single-doc
data:
  key: "value"
`
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

	singleDocJson := `{
  "apiVersion": "v1",
  "kind": "ConfigMap",
  "metadata": {
    "name": "single-doc-json"
  },
  "data": {
    "key": "value"
  }
}
`
	multiDocJson := `[
  {
    "apiVersion": "v1",
    "kind": "ConfigMap",
    "metadata": {
      "name": "config-one-json"
    }
  },
  {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "deploy-two-json"
    }
  }
]`

	cases := []struct {
		name                string
		serverSideDryRun    bool
		kubeconfigPath      string
		ignoreFields        []string
		productFiles        map[string]string
		expectDocsCount     int
		expectSubjectsCount int
		expectSkipNoError   bool
		checkIgnoreFields   bool
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
				"readme.txt": "not a manifest file",
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
		{
			name: "SingleDocJson",
			productFiles: map[string]string{
				"config.json": singleDocJson,
			},
			expectDocsCount:     1,
			expectSubjectsCount: 1,
		},
		{
			name: "MultiDocJson",
			productFiles: map[string]string{
				"multi.json": multiDocJson,
			},
			expectDocsCount:     2,
			expectSubjectsCount: 2,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			var products map[string]attestation.Product
			if c.productFiles != nil {
				products = make(map[string]attestation.Product, len(c.productFiles))
				for fname, content := range c.productFiles {
					fullPath := filepath.Join(tmpDir, fname)
					require.NoError(t, os.WriteFile(fullPath, []byte(content), 0o600))

					dig, err := cryptoutil.CalculateDigestSetFromFile(fullPath, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
					require.NoError(t, err)

					// If .json, set MIME to application/json; else default to text/yaml
					if strings.HasSuffix(strings.ToLower(fname), ".json") {
						products[fname] = attestation.Product{
							MimeType: "application/json",
							Digest:   dig,
						}
					} else {
						products[fname] = attestation.Product{
							MimeType: "text/yaml",
							Digest:   dig,
						}
					}
				}
			}

			prod := producter{
				name:     "test-products",
				runType:  attestation.ProductRunType,
				products: products,
			}

			km := k8smanifest.New()
			if c.serverSideDryRun {
				k8smanifest.WithServerSideDryRun(true)(km)
			}
			if c.kubeconfigPath != "" {
				k8smanifest.WithKubeconfigPath(c.kubeconfigPath)(km)
			}
			if len(c.ignoreFields) > 0 {
				k8smanifest.WithExtraIgnoreFields(c.ignoreFields...)(km)
			}

			ctx, err := attestation.NewContext(
				"k8s-table-test",
				[]attestation.Attestor{prod, km},
				attestation.WithWorkingDir(tmpDir),
			)
			require.NoError(t, err)

			err = ctx.RunAttestors()
			if c.expectSkipNoError {
				require.NoError(t, err, "attestor should skip gracefully, not fail")
			} else {
				require.NoError(t, err)
			}

			require.Len(t, km.RecordedDocs, c.expectDocsCount, "RecordedDocs mismatch")
			subs := km.Subjects()
			require.Len(t, subs, c.expectSubjectsCount, "Subjects mismatch")

			if c.checkIgnoreFields {
				sch := km.Schema()
				require.True(t, hasPropertyKeyInAttestor(sch, "IgnoreFields"),
					"the schema should have 'IgnoreFields' in Attestor.Properties")
			}
		})
	}
}

func TestK8smanifest_NoProducts(t *testing.T) {
	km := k8smanifest.New()
	ctx, err := attestation.NewContext("k8s-test", []attestation.Attestor{km})
	require.NoError(t, err)

	err = ctx.RunAttestors()
	require.NoError(t, err, "should skip if no products found, not fail")
	require.Empty(t, km.RecordedDocs, "no products => no recorded docs")
	require.Empty(t, km.Subjects(), "no products => no subjects")
}

func TestK8smanifest_NoYaml(t *testing.T) {
	tmpDir := t.TempDir()

	path := filepath.Join(tmpDir, "readme.txt")
	require.NoError(t, os.WriteFile(path, []byte("some text"), 0o600))

	dig, err := cryptoutil.CalculateDigestSetFromFile(path, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)

	prod := producter{
		name:    "dummy",
		runType: attestation.ProductRunType,
		products: map[string]attestation.Product{
			"readme.txt": {MimeType: "text/plain", Digest: dig},
		},
	}

	km := k8smanifest.New()
	ctx, err := attestation.NewContext("k8s-test", []attestation.Attestor{prod, km},
		attestation.WithWorkingDir(tmpDir),
	)
	require.NoError(t, err)

	err = ctx.RunAttestors()
	require.NoError(t, err, "should skip if no .yaml or .json found, not fail")
	require.Empty(t, km.RecordedDocs)
	require.Empty(t, km.Subjects())
}

func TestK8smanifest_Simple(t *testing.T) {
	tmpDir := t.TempDir()

	data := `apiVersion: v1
kind: ConfigMap
metadata:
  name: my-config
data:
  key: "value"
`
	f := filepath.Join(tmpDir, "config.yaml")
	require.NoError(t, os.WriteFile(f, []byte(data), 0o600))

	dig, err := cryptoutil.CalculateDigestSetFromFile(f, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)

	prod := producter{
		name:    "dummy",
		runType: attestation.ProductRunType,
		products: map[string]attestation.Product{
			"config.yaml": {MimeType: "text/yaml", Digest: dig},
		},
	}

	km := k8smanifest.New()
	ctx, err := attestation.NewContext("k8s-simple", []attestation.Attestor{prod, km},
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
		attestation.WithWorkingDir(tmpDir),
	)
	require.NoError(t, err)

	require.NoError(t, ctx.RunAttestors())
	subs := km.Subjects()
	require.NotEmpty(t, subs)

	require.Len(t, km.RecordedDocs, 1)
	doc := km.RecordedDocs[0]
	require.Equal(t, "my-config", doc.Name)
	require.Equal(t, "ConfigMap", doc.Kind)
	require.NotEmpty(t, doc.CanonicalJSON)
	require.NotEmpty(t, doc.ComputedDigest)

	var foundKey string
	for k := range subs {
		if strings.Contains(k, "k8smanifest:config.yaml:ConfigMap:my-config") {
			foundKey = k
			break
		}
	}
	require.NotEmpty(t, foundKey, "Expected to find a subject key with kind=ConfigMap and name=my-config")
}

func TestK8smanifest_MultiDoc(t *testing.T) {
	tmpDir := t.TempDir()

	data := `apiVersion: v1
kind: ConfigMap
metadata:
  name: config-one
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: deploy-two
`
	f := filepath.Join(tmpDir, "multi.yaml")
	require.NoError(t, os.WriteFile(f, []byte(data), 0o600))

	dig, err := cryptoutil.CalculateDigestSetFromFile(f, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)

	prod := producter{
		name:    "dummy",
		runType: attestation.ProductRunType,
		products: map[string]attestation.Product{
			"multi.yaml": {MimeType: "text/yaml", Digest: dig},
		},
	}

	km := k8smanifest.New()
	ctx, err := attestation.NewContext("k8s-multidoc", []attestation.Attestor{prod, km},
		attestation.WithWorkingDir(tmpDir),
	)
	require.NoError(t, err)

	require.NoError(t, ctx.RunAttestors())
	subs := km.Subjects()

	require.Len(t, km.RecordedDocs, 2)
	require.Len(t, subs, 2)

	var foundConfig, foundDeploy bool
	for k := range subs {
		if strings.Contains(k, "k8smanifest:multi.yaml:ConfigMap:config-one") {
			foundConfig = true
		} else if strings.Contains(k, "k8smanifest:multi.yaml:Deployment:deploy-two") {
			foundDeploy = true
		}
	}
	require.True(t, foundConfig, "Should find a subject referencing config-one")
	require.True(t, foundDeploy, "Should find a subject referencing deploy-two")
}

func TestK8smanifest_IgnoresEphemeral(t *testing.T) {
	tmpDir := t.TempDir()

	data := `apiVersion: v1
kind: Pod
metadata:
  name: ephemeral-pod
  uid: 12345
  resourceVersion: "999"
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: "something"
    witness.dev/content-hash: "abcxyz"
    app.kubernetes.io/name: "hello"
status:
  ready: false
`
	f := filepath.Join(tmpDir, "ephemeral.yaml")
	require.NoError(t, os.WriteFile(f, []byte(data), 0o600))

	dig, err := cryptoutil.CalculateDigestSetFromFile(f, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)

	prod := producter{
		name:    "dummy",
		runType: attestation.ProductRunType,
		products: map[string]attestation.Product{
			"ephemeral.yaml": {MimeType: "text/yaml", Digest: dig},
		},
	}

	km := k8smanifest.New()
	ctx, err := attestation.NewContext("k8s-ephemeral", []attestation.Attestor{prod, km},
		attestation.WithWorkingDir(tmpDir),
	)
	require.NoError(t, err)

	require.NoError(t, ctx.RunAttestors())
	subs := km.Subjects()

	require.Len(t, km.RecordedDocs, 1)
	require.Len(t, subs, 1)

	doc := km.RecordedDocs[0]
	require.Equal(t, "ephemeral-pod", doc.Name)
	require.Contains(t, doc.SubjectKey, "k8smanifest:ephemeral.yaml:Pod:ephemeral-pod")

	// doc.Data is the raw JSON after ephemeral removal & canonicalization
	// Actually doc.Data is pre-canonical, but ephemeral fields should be removed from it too
	var payload map[string]interface{}
	err = json.Unmarshal(doc.Data, &payload)
	require.NoError(t, err)

	md, ok := payload["metadata"].(map[string]interface{})
	require.True(t, ok, "metadata should be present as a map")
	require.NotContains(t, md, "uid", "UID should be removed as ephemeral")
	require.NotContains(t, md, "resourceVersion", "resourceVersion should be removed as ephemeral")

	annotations, ok := md["annotations"].(map[string]interface{})
	require.True(t, ok, "annotations should be a map if present")
	require.NotContains(t, annotations, "witness.dev/content-hash", "should remove ephemeral annotation")

	_, hasStatus := payload["status"]
	require.False(t, hasStatus, "status field should be removed as ephemeral")
}

func TestK8smanifest_WithServerSideDryRunAndKubeconfig(t *testing.T) {
	km := k8smanifest.New()
	require.False(t, km.ServerSideDryRun)
	require.Empty(t, km.KubeconfigPath)

	k8smanifest.WithServerSideDryRun(true)(km)
	require.True(t, km.ServerSideDryRun)

	k8smanifest.WithKubeconfigPath("/path/to/kubeconfig")(km)
	require.Equal(t, "/path/to/kubeconfig", km.KubeconfigPath)
}

func TestK8smanifest_WithExtraIgnoreAnnotations(t *testing.T) {
	km := k8smanifest.New()
	require.Empty(t, km.IgnoreAnnotations)

	k8smanifest.WithExtraIgnoreAnnotations("witness.dev/special-annotation")(km)
	require.Contains(t, km.IgnoreAnnotations, "witness.dev/special-annotation")
}

func TestK8smanifest_WithExtraIgnoreFields(t *testing.T) {
	km := k8smanifest.New()
	require.Empty(t, km.IgnoreFields)

	k8smanifest.WithExtraIgnoreFields("metadata.labels.myorg")(km)
	require.Contains(t, km.IgnoreFields, "metadata.labels.myorg")

	sch := km.Schema()
	require.NotNil(t, sch)
	require.True(t, hasPropertyKeyInAttestor(sch, "IgnoreFields"),
		"the schema should have 'IgnoreFields' in Attestor.Properties")
}

func TestK8smanifest_SimpleJson(t *testing.T) {
	tmpDir := t.TempDir()

	data := `{
  "apiVersion": "v1",
  "kind": "ConfigMap",
  "metadata": {
    "name": "my-config-json"
  },
  "data": {
    "key": "value"
  }
}
`
	f := filepath.Join(tmpDir, "config.json")
	require.NoError(t, os.WriteFile(f, []byte(data), 0o600))

	dig, err := cryptoutil.CalculateDigestSetFromFile(f, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)

	prod := producter{
		name:    "dummy",
		runType: attestation.ProductRunType,
		products: map[string]attestation.Product{
			"config.json": {MimeType: "application/json", Digest: dig},
		},
	}

	km := k8smanifest.New()
	ctx, err := attestation.NewContext("k8s-simple-json", []attestation.Attestor{prod, km},
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
		attestation.WithWorkingDir(tmpDir),
	)
	require.NoError(t, err)

	require.NoError(t, ctx.RunAttestors())
	subs := km.Subjects()
	require.NotEmpty(t, subs)

	require.Len(t, km.RecordedDocs, 1)
	doc := km.RecordedDocs[0]
	require.Equal(t, "my-config-json", doc.Name)
	require.Equal(t, "ConfigMap", doc.Kind)
	require.NotEmpty(t, doc.CanonicalJSON)
	require.NotEmpty(t, doc.ComputedDigest)

	var foundKey string
	for k := range subs {
		if strings.Contains(k, "k8smanifest:config.json:ConfigMap:my-config-json") {
			foundKey = k
			break
		}
	}
	require.NotEmpty(t, foundKey)
}

func TestK8smanifest_MultiDocJson(t *testing.T) {
	tmpDir := t.TempDir()

	data := `[
  {
    "apiVersion": "v1",
    "kind": "ConfigMap",
    "metadata": {
      "name": "config-one-json"
    }
  },
  {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "deploy-two-json"
    }
  }
]`
	f := filepath.Join(tmpDir, "multi.json")
	require.NoError(t, os.WriteFile(f, []byte(data), 0o600))

	dig, err := cryptoutil.CalculateDigestSetFromFile(f, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)

	prod := producter{
		name:    "dummy",
		runType: attestation.ProductRunType,
		products: map[string]attestation.Product{
			"multi.json": {MimeType: "application/json", Digest: dig},
		},
	}

	km := k8smanifest.New()
	ctx, err := attestation.NewContext("k8s-multidoc-json", []attestation.Attestor{prod, km},
		attestation.WithWorkingDir(tmpDir),
	)
	require.NoError(t, err)

	require.NoError(t, ctx.RunAttestors())
	subs := km.Subjects()

	require.Len(t, km.RecordedDocs, 2)
	require.Len(t, subs, 2)

	var foundConfig, foundDeploy bool
	for k := range subs {
		if strings.Contains(k, "k8smanifest:multi.json:ConfigMap:config-one-json") {
			foundConfig = true
		} else if strings.Contains(k, "k8smanifest:multi.json:Deployment:deploy-two-json") {
			foundDeploy = true
		}
	}
	require.True(t, foundConfig)
	require.True(t, foundDeploy)
}
