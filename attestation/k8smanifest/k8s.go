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

package k8smanifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/registry"
	"github.com/invopop/jsonschema"
	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
)

// Name is the identifier for this attestor.
const Name = "k8smanifest"

// Type is the URI identifying the predicate type.
const Type = "https://witness.dev/attestations/k8smanifest/v0.2"

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
	FilePath       string          `json:"filepath"`
	Kind           string          `json:"kind"`
	Name           string          `json:"name"`
	Data           json.RawMessage `json:"data"`
	SubjectKey     string          `json:"subjectkey"`
	RecordedImages []RecordedImage `json:"recordedimages"`
}

type ClusterInfo struct {
	Server string `json:"server"`
}

// Recorded image stores the details of images found in kubernetes manifests
type RecordedImage struct {
	Reference string            `json:"reference"`
	Digest    map[string]string `json:"digest"`
}

// Attestor implements the Witness Attestor interface for Kubernetes manifests.
type Attestor struct {
	ServerSideDryRun  bool     `json:"serversidedryrun,omitempty"`
	RecordClusterInfo bool     `json:"recordclusterinfo,omitempty"`
	KubeconfigPath    string   `json:"kubeconfig,omitempty"`
	KubeContext       string   `json:"kubecontext,omitempty"`
	IgnoreFields      []string `json:"ignorefields,omitempty" jsonschema:"title=ignorefields"`
	IgnoreAnnotations []string `json:"ignoreannotations,omitempty"`
	ephemeralFields   []string
	ephemeralAnn      []string
	RecordedDocs      []RecordedObject `json:"recordeddocs,omitempty"`
	subjectDigests    sync.Map
	ClusterInfo       ClusterInfo `json:"clusterinfo"`
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
			clientcmd.RecommendedHomeFile,
			func(a attestation.Attestor, val string) (attestation.Attestor, error) {
				km, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithKubeconfigPath(val)(km)
				return km, nil
			},
		),
		registry.StringConfigOption(
			"context",
			"The kubernetes context that this step applies to (if not set in the kubeconfig)",
			"",
			func(a attestation.Attestor, val string) (attestation.Attestor, error) {
				km, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithKubeContext(val)(km)
				return km, nil
			},
		),
		registry.BoolConfigOption(
			"record-cluster-information",
			"Record information about the cluster that the client has a connection to",
			true,
			func(a attestation.Attestor, val bool) (attestation.Attestor, error) {
				km, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("invalid attestor type: %T", a)
				}
				WithRecordClusterInfo(val)(km)
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

		ephemeralFields: defaultEphemeralFields,
		ephemeralAnn:    defaultEphemeralAnnotations,

		RecordedDocs: []RecordedObject{},
	}
}

// WithServerSideDryRun sets the server-side dry-run option.
func WithServerSideDryRun(dryRun bool) func(*Attestor) {
	return func(a *Attestor) {
		a.ServerSideDryRun = dryRun
	}
}

// WithKubeconfigPath sets the kubeconfig path used in server-side dry-run.
func WithKubeconfigPath(path string) func(*Attestor) {
	return func(a *Attestor) {
		a.KubeconfigPath = path
	}
}

// WithKubeContext sets the kubeconfig path used in server-side dry-run.
func WithKubeContext(context string) func(*Attestor) {
	return func(a *Attestor) {
		a.KubeContext = context
	}
}

// WithRecordClusterInfo sets the cluster information recording option.
func WithRecordClusterInfo(record bool) func(*Attestor) {
	return func(a *Attestor) {
		a.RecordClusterInfo = record
	}
}

// WithExtraIgnoreFields appends additional ephemeral fields to ignore.
func WithExtraIgnoreFields(fields ...string) func(*Attestor) {
	return func(a *Attestor) {
		a.IgnoreFields = append(a.IgnoreFields, fields...)
		a.ephemeralFields = append(defaultEphemeralFields, a.IgnoreFields...)
	}
}

// WithExtraIgnoreAnnotations appends additional ephemeral annotations to ignore.
func WithExtraIgnoreAnnotations(anns ...string) func(*Attestor) {
	return func(a *Attestor) {
		a.IgnoreAnnotations = append(a.IgnoreAnnotations, anns...)
		a.ephemeralAnn = append(defaultEphemeralAnnotations, a.IgnoreAnnotations...)
	}
}

// Name satisfies the Attestor interface.
func (a *Attestor) Name() string {
	return Name
}

// Type satisfies the Attestor interface.
func (a *Attestor) Type() string {
	return Type
}

// RunType satisfies the Attestor interface.
func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

// Schema provides a JSON schema for this attestor.
func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(a)
}

// Attest processes any YAML/JSON products, removes ephemeral fields, etc.
func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	products := ctx.Products()

	// skip if no products
	if len(products) == 0 {
		log.Warn("no products found, skipping k8smanifest attestor")
		return nil
	}

	if a.RecordClusterInfo {
		err := a.runRecordClusterInfo()
		if err != nil {
			return err
		}
	}

	// skip if no .yaml/.yml/.json found
	hasYamlOrJSON := false
	for path := range products {
		if isJSONorYAML(path) {
			hasYamlOrJSON = true
			break
		}
	}
	if !hasYamlOrJSON {
		log.Warn("did not find any .json, .yaml or .yml file among products, skipping k8smanifest attestor")
		return nil
	}

	parsedAnything := false
	for path := range products {
		if !isJSONorYAML(path) {
			continue
		}
		fullPath := filepath.Join(ctx.WorkingDir(), path)
		content, err := os.ReadFile(fullPath)
		if err != nil {
			log.Debugf("failed reading file %s: %v", fullPath, err)
			continue
		}

		// Decide whether to parse as JSON or split as YAML
		ext := strings.ToLower(filepath.Ext(path))
		var docs [][]byte
		if ext == ".json" {
			// If it's valid JSON, handle it
			if !json.Valid(content) {
				log.Debugf("invalid JSON found in %s, skipping", path)
				continue
			}
			var top interface{}
			if err := json.Unmarshal(content, &top); err != nil {
				log.Debugf("cannot unmarshal top-level JSON in %s: %v", path, err)
				continue
			}
			switch arr := top.(type) {
			case []interface{}:
				// each array entry is a doc
				for _, el := range arr {
					elBytes, e := json.Marshal(el)
					if e == nil {
						docs = append(docs, elBytes)
					}
				}
			default:
				// single doc
				docs = append(docs, content)
			}
		} else {
			// YAML path
			docs, err = splitYAMLDocs(content)
			if err != nil {
				log.Debugf("Failed to split YAML docs for %s: %v", path, err)
				continue
			}
		}

		for _, doc := range docs {
			var rawDoc interface{}
			if e := json.Unmarshal(doc, &rawDoc); e != nil {
				log.Debugf("Failed to unmarshal doc to JSON from %s: %v", path, e)
				continue
			}

			docMap, ok := rawDoc.(map[string]interface{})
			if !ok || docMap == nil {
				continue
			}

			// processDoc does ephemeral removal
			cleanBytes, recorded, err := a.processDoc(docMap, path)
			if err != nil {
				log.Debugf("error processing doc in %s: %v", path, err)
				continue
			}

			recorded.Data = cleanBytes
			a.RecordedDocs = append(a.RecordedDocs, recorded)

			parsedAnything = true
		}
	}

	if !parsedAnything {
		log.Warn("did not parse any valid yaml or json docs in k8smanifest attestor, skipping")
	}

	return nil
}

// processDoc strips ephemeral fields, optionally does a server-side dry-run,
// then returns the cleaned JSON bytes plus a RecordedObject (without final digest).
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

	// remove ephemeral fields/annotations
	a.removeEphemeralFields(finalObj)

	// ephemeral-cleaned JSON
	cleanBytes, err := json.Marshal(finalObj)
	if err != nil {
		return nil, RecordedObject{}, fmt.Errorf("marshal error: %w", err)
	}

	decode := scheme.Codecs.UniversalDeserializer().Decode

	obj, gvk, err := decode(cleanBytes, nil, nil)
	if err != nil {
		err := fmt.Errorf("Failed to decode file %s. Continuing: %s", filePath, err.Error())
		log.Debugf("(attestation/k8smanifest) %w", err)
		return nil, RecordedObject{}, err
	}

	kindVal := "UnknownKind"
	if len(gvk.Kind) > 0 {
		kindVal = gvk.Kind
	}

	nameVal := "unknown"
	if md, ok := finalObj["metadata"].(map[string]interface{}); ok && md != nil {
		if nm, ok := md["name"].(string); ok && nm != "" {
			nameVal = nm
		}
	}

	recordedImages := []RecordedImage{}
	if list, ok := obj.(*corev1.List); ok {
		for _, obj := range list.Items {
			o, gvk, err := decode(obj.Raw, nil, nil)
			if err != nil {
				err := fmt.Errorf("Failed to decode file %s. Continuing: %s", filePath, err.Error())
				log.Debugf("(attestation/k8smanifest) %w", err)
				return nil, RecordedObject{}, err
			}

			recordedImages = append(recordedImages, recordImages(o, gvk)...)
		}
	} else {
		recordedImages = recordImages(obj, gvk)
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

	rec := RecordedObject{
		FilePath:       filePath,
		Kind:           kindVal,
		Name:           nameVal,
		SubjectKey:     subjectKey,
		RecordedImages: recordedImages,
	}

	// Return the cleaned bytes and the RecordedObject skeleton
	return cleanBytes, rec, nil
}

func (a *Attestor) runRecordClusterInfo() error {
	log.Info("(attestation/k8smanifest) recording cluster information")
	config, err := clientcmd.LoadFromFile(a.KubeconfigPath)
	if err != nil {
		return err
	}

	cc := a.KubeContext
	if cc == "" && config.CurrentContext != "" {
		cc = config.CurrentContext
	}

	if cc == "" {
		return fmt.Errorf("kubernetes context not set")
	}

	log.Debugf("(attestation/k8smanifest) checking cluster information for context '%s'", cc)

	if cluster, ok := config.Clusters[cc]; ok {
		a.ClusterInfo.Server = cluster.Server
		return nil
	}

	return fmt.Errorf("unable to find context '%s' in kubernetes config at path '%s'", cc, a.KubeconfigPath)
}

// runDryRun executes kubectl apply --dry-run=server -o json -f -
// to generate server-defaulted resource content.
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

// removeEphemeralFields removes ephemeral fields & ephemeral annotations from the doc.
func (a *Attestor) removeEphemeralFields(obj map[string]interface{}) {
	for _, ef := range a.ephemeralFields {
		removeNested(obj, ef)
	}
	removeEphemeralAnnotations(obj, a.ephemeralAnn)
}

// removeNested handles dot-separated paths, e.g. "metadata.name" or "status.something".
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

// removeEphemeralAnnotations removes ephemeral annotation keys from metadata.annotations.
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

// isJSONorYAML checks if a file name ends with .json, .yaml, or .yml.
func isJSONorYAML(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".json" || ext == ".yaml" || ext == ".yml"
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

// splitYAMLDocs decodes multiple YAML documents. If none are found, it falls back to raw JSON check.
// This is copied from the structured data attestor, with minimal changes.
func splitYAMLDocs(content []byte) ([][]byte, error) {
	var out [][]byte
	dec := yaml.NewDecoder(bytes.NewReader(content))
	docIndex := 0
	for {
		var raw interface{}
		err := dec.Decode(&raw)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "eof") ||
				strings.Contains(strings.ToLower(err.Error()), "document is empty") {
				log.Debugf("splitYAMLDocs: stopping decode on docIndex=%d (EOF or empty doc)", docIndex)
				break
			}
			// Log a warning and break from the decode loop, preserving prior docs
			log.Warnf("splitYAMLDocs: error decoding docIndex=%d: %v", docIndex, err)
			break
		}
		raw = convertKeys(raw)
		j, err := json.Marshal(raw)
		if err != nil {
			log.Debugf("splitYAMLDocs: could not marshal docIndex=%d to JSON: %v", docIndex, err)
			continue
		}
		log.Debugf("splitYAMLDocs: docIndex=%d => %s", docIndex, string(j))
		out = append(out, j)
		docIndex++
	}
	// If no docs were parsed, maybe it's raw JSON
	if len(out) == 0 && json.Valid(content) {
		log.Debugf("splitYAMLDocs: no YAML docs but valid JSON. Using entire file as one doc.")
		out = append(out, content)
	} else if len(out) == 0 {
		log.Warnf("splitYAMLDocs: no valid YAML or JSON found.")
	}
	return out, nil
}

// convertKeys recursively converts map[interface{}]interface{} to map[string]interface{},
// so json.Marshal(...) won't fail on "unsupported type: map[interface{}]interface{}".
func convertKeys(value interface{}) interface{} {
	switch v := value.(type) {
	case map[interface{}]interface{}:
		m2 := make(map[string]interface{})
		for key, val := range v {
			kStr := fmt.Sprintf("%v", key)
			m2[kStr] = convertKeys(val)
		}
		return m2
	case []interface{}:
		for i := range v {
			v[i] = convertKeys(v[i])
		}
		return v
	default:
		return v
	}
}

func recordImages(obj runtime.Object, gvk *schema.GroupVersionKind) []RecordedImage {
	recordedImages := []RecordedImage{}
	switch gvk.Kind {
	case "Pod":
		for _, c := range obj.(*corev1.Pod).Spec.Containers {
			recordedImages = append(recordedImages, newRecordedImage(c.Image))
		}
	case "Deployment":
		for _, c := range obj.(*appsv1.Deployment).Spec.Template.Spec.Containers {
			recordedImages = append(recordedImages, newRecordedImage(c.Image))
		}
	case "ReplicaSet":
		for _, c := range obj.(*appsv1.ReplicaSet).Spec.Template.Spec.Containers {
			recordedImages = append(recordedImages, newRecordedImage(c.Image))
		}
	case "StatefulSet":
		for _, c := range obj.(*appsv1.StatefulSet).Spec.Template.Spec.Containers {
			recordedImages = append(recordedImages, newRecordedImage(c.Image))
		}
	case "DaemonSet":
		for _, c := range obj.(*appsv1.DaemonSet).Spec.Template.Spec.Containers {
			recordedImages = append(recordedImages, newRecordedImage(c.Image))
		}
	case "Job":
		for _, c := range obj.(*batchv1.Job).Spec.Template.Spec.Containers {
			recordedImages = append(recordedImages, newRecordedImage(c.Image))
		}
	case "CronJob":
		for _, c := range obj.(*batchv1.CronJob).Spec.JobTemplate.Spec.Template.Spec.Containers {
			recordedImages = append(recordedImages, newRecordedImage(c.Image))
		}
		// NOTE: there are likely a bunch of other list types that we should support here
	default:
		log.Debugf("(attestation/k8smanifest) Manifest of kind %s cannot be parsed to find images", gvk.Kind)
	}

	return recordedImages
}

func newRecordedImage(image string) RecordedImage {
	rc := RecordedImage{
		Reference: image,
		Digest:    make(map[string]string),
	}

	dig, err := DigestForRef(rc.Reference)
	if err == nil && dig != "" {
		if spl := strings.Split(dig, ":"); len(spl) == 2 {
			rc.Digest[spl[0]] = spl[1]
		} else {
			log.Debugf("(attestation/k8smanifest) unrecognised structure for digest '%s'", rc.Reference)
		}
	} else {
		log.Debugf("(attestation/k8smanifest) failed to get digest for reference %s: %s", rc.Reference, err.Error())
	}

	return rc
}
