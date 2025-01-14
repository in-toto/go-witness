package k8smanifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/registry"
	"github.com/invopop/jsonschema"
)

// Name is the identifier for this attestor.
const Name = "k8smanifest"

// Type is the URI identifying the predicate type.
const Type = "https://witness.dev/attestations/k8smanifest/v0.1"

// RunType is the run stage at which this attestor is executed.
const RunType = attestation.PostProductRunType

// Default ephemeral fields to remove.
var defaultEphemeralFields = []string{
	"metadata.resourceVersion",
	"metadata.uid",
	"metadata.creationTimestamp",
	"metadata.managedFields",
	"metadata.generation",
	"status",
}

// Default ephemeral annotations to remove.
var defaultEphemeralAnnotations = []string{
	"kubectl.kubernetes.io/last-applied-configuration",
	"deployment.kubernetes.io/revision",
	"witness.dev/content-hash",
	"cosign.sigstore.dev/message",
	"cosign.sigstore.dev/signature",
	"cosign.sigstore.dev/bundle",
}

// RecordedObject stores ephemeral-cleaned doc details.
type RecordedObject struct {
	FilePath       string                 `json:"filePath"`
	Kind           string                 `json:"kind"`
	Name           string                 `json:"name"`
	Data           map[string]interface{} `json:"data"`
	CanonicalJSON  string                 `json:"canonicalJSON"`
	SubjectKey     string                 `json:"subjectKey"`
	ComputedDigest cryptoutil.DigestSet   `json:"computedDigest"`
}

// Attestor implements the Witness Attestor interface for Kubernetes manifests.
type Attestor struct {
	ServerSideDryRun  bool     `json:"server_side_dry_run,omitempty"`
	KubeconfigPath    string   `json:"kubeconfig,omitempty"`
	IgnoreFields      []string `json:"IgnoreFields,omitempty" jsonschema:"title=IgnoreFields"`
	IgnoreAnnotations []string `json:"IgnoreAnnotations,omitempty"`

	// ephemeral fields actually used at runtime
	ephemeralFields      []string
	ephemeralAnnotations []string

	// RecordedDocs is the final ephemeral-cleaned docs
	RecordedDocs []RecordedObject `json:"recorded_docs,omitempty"`

	// subjectDigests is concurrency-safe for implementing Subjecter
	subjectDigests sync.Map
}

var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
)

func init() {
	attestation.RegisterAttestation(
		Name,
		Type,
		RunType,
		func() attestation.Attestor {
			return New()
		},
		registry.BoolConfigOption(
			"server-side-dry-run",
			"Perform a server-side dry-run to normalize resource defaults before hashing",
			false,
			func(a attestation.Attestor, val bool) (attestation.Attestor, error) {
				km, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithServerSideDryRun(val)(km)
				return km, nil
			},
		),
		registry.StringConfigOption(
			"kubeconfig",
			"Path to the kubeconfig file (used during server-side dry-run)",
			"",
			func(a attestation.Attestor, val string) (attestation.Attestor, error) {
				km, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithKubeconfigPath(val)(km)
				return km, nil
			},
		),
		registry.StringSliceConfigOption(
			"ignore-fields",
			"Additional ephemeral fields to remove (dot-separated), e.g., metadata.annotations.myorg",
			nil,
			func(a attestation.Attestor, fields []string) (attestation.Attestor, error) {
				km, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithExtraIgnoreFields(fields...)(km)
				return km, nil
			},
		),
		registry.StringSliceConfigOption(
			"ignore-annotations",
			"Additional ephemeral annotations to remove, e.g. witness.dev/another-ephemeral",
			nil,
			func(a attestation.Attestor, ann []string) (attestation.Attestor, error) {
				km, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithExtraIgnoreAnnotations(ann...)(km)
				return km, nil
			},
		),
	)
}

// New returns a default Attestor
func New() *Attestor {
	return &Attestor{
		ServerSideDryRun:  false,
		KubeconfigPath:    "",
		IgnoreFields:      []string{},
		IgnoreAnnotations: []string{},

		ephemeralFields:      defaultEphemeralFields,
		ephemeralAnnotations: defaultEphemeralAnnotations,
		RecordedDocs:         []RecordedObject{},
	}
}

// Functional options for customizing behavior

func WithServerSideDryRun(dryRun bool) func(*Attestor) {
	return func(a *Attestor) {
		a.ServerSideDryRun = dryRun
	}
}

func WithKubeconfigPath(path string) func(*Attestor) {
	return func(a *Attestor) {
		a.KubeconfigPath = path
	}
}

func WithExtraIgnoreFields(fields ...string) func(*Attestor) {
	return func(a *Attestor) {
		a.IgnoreFields = append(a.IgnoreFields, fields...)
		a.ephemeralFields = append(defaultEphemeralFields, a.IgnoreFields...)
	}
}

func WithExtraIgnoreAnnotations(ann ...string) func(*Attestor) {
	return func(a *Attestor) {
		a.IgnoreAnnotations = append(a.IgnoreAnnotations, ann...)
		a.ephemeralAnnotations = append(defaultEphemeralAnnotations, a.IgnoreAnnotations...)
	}
}

// Name satisfies Attestor interface
func (a *Attestor) Name() string {
	return Name
}

// Type satisfies Attestor interface
func (a *Attestor) Type() string {
	return Type
}

// RunType satisfies Attestor interface
func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

// Schema provides a JSON schema for this attestor
func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(a)
}

// Attest is the main entry point
// We skip if no products or no YAML are found
func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	products := ctx.Products()

	// skip if no products
	if len(products) == 0 {
		log.Warn("no products found, skipping k8smanifest attestor")
		return nil // no error
	}

	// skip if no .yaml or .yml
	hasYaml := false
	for path := range products {
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			hasYaml = true
			break
		}
	}
	if !hasYaml {
		log.Warn("did not find any .yaml or .yml file among products, skipping k8smanifest attestor")
		return nil
	}

	parsedAnything := false
	for path := range products {
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		fullPath := filepath.Join(ctx.WorkingDir(), path)
		content, err := os.ReadFile(fullPath)
		if err != nil {
			log.Debugf("failed reading file %s: %v", fullPath, err)
			continue
		}

		dec := yaml.NewDecoder(bytes.NewReader(content))
		for {
			var raw interface{}
			if err := dec.Decode(&raw); err != nil {
				if strings.Contains(strings.ToLower(err.Error()), "eof") ||
					strings.Contains(strings.ToLower(err.Error()), "document is empty") {
					break
				}
				log.Debugf("failed decoding YAML doc in %s: %v", path, err)
				break
			}

			docMap, ok := raw.(map[string]interface{})
			if !ok || docMap == nil {
				continue
			}

			canonBytes, recorded, err := a.processDoc(docMap, path)
			if err != nil {
				log.Debugf("error processing doc in %s: %v", path, err)
				continue
			}

			a.RecordedDocs = append(a.RecordedDocs, recorded)

			ds, err := cryptoutil.CalculateDigestSetFromBytes(canonBytes, ctx.Hashes())
			if err != nil {
				log.Debugf("failed hashing doc in %s: %v", path, err)
				continue
			}

			a.RecordedDocs[len(a.RecordedDocs)-1].ComputedDigest = ds
			a.subjectDigests.Store(recorded.SubjectKey, ds)
			parsedAnything = true
		}
	}

	if !parsedAnything {
		log.Warn("did not parse any valid yaml docs in k8smanifest attestor, skipping")
	}

	return nil
}

// processDoc strips ephemeral fields, optionally dry-runs, canonicalizes
func (a *Attestor) processDoc(doc map[string]interface{}, filePath string) ([]byte, RecordedObject, error) {
	finalObj := doc
	if a.ServerSideDryRun {
		dryObj, err := a.runDryRun(doc)
		if err == nil {
			finalObj = dryObj
		} else {
			log.Debugf("server-side dry-run error for %s: %v", filePath, err)
		}
	}

	a.removeEphemeralFields(finalObj)
	canonStr, err := toCanonicalJSON(finalObj)
	if err != nil {
		return nil, RecordedObject{}, fmt.Errorf("canonicalization error: %w", err)
	}

	kindVal := "UnknownKind"
	if kv, ok := finalObj["kind"].(string); ok && kv != "" {
		kindVal = kv
	}
	nameVal := "unknown"
	if md, ok := finalObj["metadata"].(map[string]interface{}); ok && md != nil {
		if nm, ok := md["name"].(string); ok && nm != "" {
			nameVal = nm
		}
	}

	baseKey := fmt.Sprintf("k8smanifest:%s:%s:%s", filePath, kindVal, nameVal)
	subjectKey := baseKey
	suffix := 1
	for {
		_, loaded := a.subjectDigests.Load(subjectKey)
		if !loaded {
			break
		}
		suffix++
		subjectKey = fmt.Sprintf("%s#%d", baseKey, suffix)
	}

	ro := RecordedObject{
		FilePath:      filePath,
		Kind:          kindVal,
		Name:          nameVal,
		Data:          finalObj,
		CanonicalJSON: canonStr,
		SubjectKey:    subjectKey,
	}

	return []byte(canonStr), ro, nil
}

// runDryRun executes kubectl apply --dry-run=server -o json -f -
func (a *Attestor) runDryRun(doc map[string]interface{}) (map[string]interface{}, error) {
	y, err := yaml.Marshal(doc)
	if err != nil {
		return nil, err
	}
	args := []string{"apply", "--dry-run=server", "-o", "json", "-f", "-"}
	if a.KubeconfigPath != "" {
		args = append(args, "--kubeconfig", a.KubeconfigPath)
	}
	cmd := exec.Command("kubectl", args...)
	cmd.Stdin = bytes.NewReader(y)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("kubectl dry-run error: %s (output=%q)", err, string(out))
	}
	var outMap map[string]interface{}
	if e := json.Unmarshal(out, &outMap); e != nil {
		return nil, fmt.Errorf("unmarshal after dry-run: %w", e)
	}
	return outMap, nil
}

// removeEphemeralFields removes ephemeral fields & annotations
func (a *Attestor) removeEphemeralFields(obj map[string]interface{}) {
	for _, ef := range a.ephemeralFields {
		removeNested(obj, ef)
	}
	removeEphemeralAnnotations(obj, a.ephemeralAnnotations)
}

// removeNested handles dot-separated paths, e.g. "metadata.name"
func removeNested(obj map[string]interface{}, path string) {
	parts := strings.Split(path, ".")
	cur := obj
	for i := 0; i < len(parts)-1; i++ {
		sub, ok := cur[parts[i]].(map[string]interface{})
		if !ok {
			return
		}
		cur = sub
	}
	delete(cur, parts[len(parts)-1])
}

// removeEphemeralAnnotations removes ephemeral annotation keys
func removeEphemeralAnnotations(obj map[string]interface{}, ephemeralKeys []string) {
	md, _ := obj["metadata"].(map[string]interface{})
	if md == nil {
		return
	}
	ann, _ := md["annotations"].(map[string]interface{})
	if ann == nil {
		return
	}
	for _, k := range ephemeralKeys {
		delete(ann, k)
	}
}

// Subjects returns computed subject digests
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	out := make(map[string]cryptoutil.DigestSet)
	a.subjectDigests.Range(func(k, v interface{}) bool {
		key := k.(string)
		ds := v.(cryptoutil.DigestSet)
		out[key] = ds
		return true
	})
	return out
}

// toCanonicalJSON performs stable JSON encoding
func toCanonicalJSON(v interface{}) (string, error) {
	var sb strings.Builder
	if err := encodeCanonical(v, &sb); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func encodeCanonical(val interface{}, sb *strings.Builder) error {
	switch x := val.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		if x {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case int:
		sb.WriteString(strconv.Itoa(x))
	case int64:
		sb.WriteString(strconv.FormatInt(x, 10))
	case float64:
		if math.Trunc(x) == x {
			sb.WriteString(strconv.FormatInt(int64(x), 10))
		} else {
			sb.WriteString(strconv.FormatFloat(x, 'g', -1, 64))
		}
	case string:
		sb.WriteString(strconv.Quote(x))
	case []interface{}:
		sb.WriteByte('[')
		for i, elem := range x {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := encodeCanonical(elem, sb); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case map[string]interface{}:
		keys := make([]string, 0, len(x))
		for kk := range x {
			keys = append(keys, kk)
		}
		sort.Strings(keys)
		sb.WriteByte('{')
		for i, kk := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(strconv.Quote(kk))
			sb.WriteByte(':')
			if err := encodeCanonical(x[kk], sb); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	default:
		return fmt.Errorf("unsupported type %T in canonical encoding", x)
	}
	return nil
}
