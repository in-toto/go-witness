package k8smanifest_test

import (
	"crypto"
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

// hasPropertyKeyInAttestor searches for a property key in s.Definitions["Attestor"].Properties.
func hasPropertyKeyInAttestor(s *jsonschema.Schema, key string) bool {
	// s.Definitions is a map[string]*Schema
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

// producter is a basic Product attestor for testing
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

func TestK8smanifest_NoProducts(t *testing.T) {
	km := k8smanifest.New()
	ctx, err := attestation.NewContext("k8s-test", []attestation.Attestor{km})
	require.NoError(t, err)

	// The attestor now "skips" if no products => no error
	err = ctx.RunAttestors()
	require.NoError(t, err, "should skip if no products found, not fail")

	require.Empty(t, km.RecordedDocs, "no products => no recorded docs")
	require.Empty(t, km.Subjects(), "no products => no subjects")
}

func TestK8smanifest_NoYaml(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.txt")
	require.NoError(t, os.WriteFile(path, []byte("hello world"), 0o600))

	dig, err := cryptoutil.CalculateDigestSetFromFile(path, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)

	prod := producter{
		name:    "dummy",
		runType: attestation.ProductRunType,
		products: map[string]attestation.Product{
			"test.txt": {MimeType: "text/plain", Digest: dig},
		},
	}
	km := k8smanifest.New()
	ctx, err := attestation.NewContext("k8s-test", []attestation.Attestor{prod, km},
		attestation.WithWorkingDir(tmpDir),
	)
	require.NoError(t, err)

	err = ctx.RunAttestors()
	require.NoError(t, err, "should skip if no .yaml found, not fail")

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
	rec := km.RecordedDocs[0]
	require.Equal(t, "my-config", rec.Name)
	require.Equal(t, "ConfigMap", rec.Kind)
	require.NotEmpty(t, rec.CanonicalJSON)
	require.NotEmpty(t, rec.ComputedDigest)

	var foundKey string
	for k := range subs {
		if strings.Contains(k, "k8smanifest:config.yaml:ConfigMap:my-config") {
			foundKey = k
			break
		}
	}
	require.NotEmpty(t, foundKey)
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
	require.Len(t, subs, 2)
	require.Len(t, km.RecordedDocs, 2)

	var foundConfig, foundDeploy bool
	for k := range subs {
		if strings.Contains(k, "k8smanifest:multi.yaml:ConfigMap:config-one") {
			foundConfig = true
		}
		if strings.Contains(k, "k8smanifest:multi.yaml:Deployment:deploy-two") {
			foundDeploy = true
		}
	}
	require.True(t, foundConfig)
	require.True(t, foundDeploy)
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
	require.Len(t, subs, 1)
	require.Len(t, km.RecordedDocs, 1)

	doc := km.RecordedDocs[0]
	require.Equal(t, "ephemeral-pod", doc.Name)
	require.Contains(t, doc.SubjectKey, "k8smanifest:ephemeral.yaml:Pod:ephemeral-pod")

	md, _ := doc.Data["metadata"].(map[string]interface{})
	require.NotNil(t, md)
	require.NotContains(t, md, "uid")
	require.NotContains(t, md, "resourceVersion")

	annotations, _ := md["annotations"].(map[string]interface{})
	require.NotNil(t, annotations)
	require.NotContains(t, annotations, "witness.dev/content-hash")

	_, hasStatus := doc.Data["status"]
	require.False(t, hasStatus)
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

	// Add an extra field
	k8smanifest.WithExtraIgnoreFields("metadata.labels.myorg")(km)
	require.Contains(t, km.IgnoreFields, "metadata.labels.myorg")

	sch := km.Schema()
	require.NotNil(t, sch)

	// Now we want to confirm "IgnoreFields" is in Attestor sub-schema
	// Because "RootRef = true" by default
	require.True(t, hasPropertyKeyInAttestor(sch, "IgnoreFields"),
		"the schema should have 'IgnoreFields' in Attestor.Properties")
}
