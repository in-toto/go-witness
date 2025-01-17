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

// Package structureddata provides an attestor for JSON/YAML files that
// canonicalizes the documents, stores all canonical JSON blobs, and
// optionally applies jq expressions to derive extra subject digests.
package structureddata

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/itchyny/gojq"
	"gopkg.in/yaml.v2"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/internal/jsoncanonicalizer"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/registry"
	"github.com/invopop/jsonschema"
)

// Name, Type, and RunType define the attestor identity and lifecycle phase.
const (
	Name    = "structureddata"
	Type    = "https://witness.dev/attestations/structureddata/v0.1"
	RunType = attestation.PostProductRunType
)

// DocumentRecord represents one canonicalized document from a file.
type DocumentRecord struct {
	FileName        string               `json:"filename"`
	OriginalDigest  cryptoutil.DigestSet `json:"originaldigest"`
	CanonicalDigest cryptoutil.DigestSet `json:"canonicaldigest"`
	Canonical       json.RawMessage      `json:"canonical"`
}

// Attestor handles multiple JSON/YAML files, storing a canonical doc for each.
type Attestor struct {
	// Documents holds the final doc records, each referencing a canonical doc.
	Documents []DocumentRecord `json:"documents"`

	// SubjectQueries is a user-supplied map of subjectName => jq expression
	// that extracts additional subject digests from the canonical doc.
	SubjectQueries map[string]string `json:"subjectqueries,omitempty"`

	// subjectDigests accumulates all computed subject digests (file-level,
	// canonical docs, and query results).
	subjectDigests map[string]cryptoutil.DigestSet
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
		func() attestation.Attestor { return New() },
		registry.StringConfigOption(
			"subject-queries",
			"subjectName=jq expression pairs (semicolon-separated). Example: 'foo=.foo;bar=.nums[]'",
			"",
			func(a attestation.Attestor, sqStr string) (attestation.Attestor, error) {
				att, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T", a)
				}
				sqMap, err := ParseSubjectQueries(sqStr)
				if err != nil {
					return a, fmt.Errorf("parseSubjectQueries: %w", err)
				}
				att.SubjectQueries = sqMap
				return att, nil
			},
		),
	)
}

// New creates a default Attestor instance.
func New() *Attestor {
	return &Attestor{
		Documents:      make([]DocumentRecord, 0),
		SubjectQueries: make(map[string]string),
		subjectDigests: make(map[string]cryptoutil.DigestSet),
	}
}

// ParseSubjectQueries parses "subjectName=jqExpr" pairs, allowing '=' inside the jq expression.
func ParseSubjectQueries(sqStr string) (map[string]string, error) {
	out := make(map[string]string)
	s := strings.TrimSpace(sqStr)
	if s == "" {
		return out, nil
	}
	pairs := strings.Split(s, ";")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid subject-queries pair %q (missing '=')", pair)
		}
		name := strings.TrimSpace(parts[0])
		expr := strings.TrimSpace(parts[1])
		if name == "" || expr == "" {
			return nil, fmt.Errorf("invalid subject-queries pair %q (empty name or expression)", pair)
		}
		out[name] = expr
	}
	return out, nil
}

// Name returns the short name ("structureddata").
func (a *Attestor) Name() string {
	return Name
}

// Type returns the attestor's URI type.
func (a *Attestor) Type() string {
	return Type
}

// RunType indicates which pipeline stage this attestor executes in.
func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

// Schema provides a JSON Schema describing this attestor.
func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(a)
}

// Attest processes each product file, handling YAML/JSON docs.
func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	prods := ctx.Products()
	if len(prods) == 0 {
		return errors.New("no products to attest")
	}

	var found bool
	for path := range prods {
		if isJSONorYAML(path) {
			found = true
			if err := a.handleFile(ctx, path); err != nil {
				log.Debugf("%s attestor skipping file %s due to error: %v", Name, path, err)
				continue
			}
		}
	}

	if !found {
		return errors.New("no .json or .yaml/.yml file found among products")
	}
	return nil
}

// Subjects returns all known subject digests from this attestor.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	return a.subjectDigests
}

// isJSONorYAML checks if a file name ends with .json, .yaml, or .yml.
func isJSONorYAML(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".json" || ext == ".yaml" || ext == ".yml"
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

// splitYAMLDocs decodes multiple YAML documents. If none are found, it falls back to raw JSON check.
func splitYAMLDocs(content []byte) ([][]byte, error) {
	var out [][]byte

	dec := yaml.NewDecoder(strings.NewReader(string(content)))
	docIndex := 0
	for {
		var raw interface{}
		err := dec.Decode(&raw)
		if err != nil {
			// If EOF or empty doc, break
			if strings.Contains(strings.ToLower(err.Error()), "eof") ||
				strings.Contains(strings.ToLower(err.Error()), "document is empty") {
				log.Debugf("splitYAMLDocs: stopping decode on docIndex=%d (EOF or empty doc)", docIndex)
				break
			}
			// Log a warning and break from the decode loop, preserving prior docs
			log.Warnf("splitYAMLDocs: error decoding docIndex=%d: %v", docIndex, err)
			break
		}
		// Convert YAML maps to JSON-friendly maps
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

// handleFile reads a single file, splits docs, canonicalizes, and stores subjects.
func (a *Attestor) handleFile(ctx *attestation.AttestationContext, path string) error {
	fullPath := filepath.Join(ctx.WorkingDir(), path)
	content, err := os.ReadFile(fullPath)
	if err != nil {
		return fmt.Errorf("could not read file %s: %w", path, err)
	}

	// Original-file digest
	origDigest, err := cryptoutil.CalculateDigestSetFromBytes(content, ctx.Hashes())
	if err != nil || len(origDigest) == 0 {
		log.Warnf("unable to compute digest for original file %s: %v", path, err)
	}
	subName := fmt.Sprintf("original-file:%s", path)
	a.subjectDigests[subName] = origDigest

	docs, err := splitYAMLDocs(content)
	if err != nil {
		log.Warnf("splitting YAML docs for %s: %v", path, err)
	}
	log.Debugf("handleFile for %s -> splitYAMLDocs => %d doc(s)", path, len(docs))

	if len(docs) == 0 {
		log.Warnf("no valid YAML/JSON documents found in %s, skipping doc", path)
		return nil
	}

	// Process each doc, skipping only the failing ones
	for docIndex, doc := range docs {
		log.Debugf("handleFile: docIndex=%d for %s => %s", docIndex, path, string(doc))

		// Canonicalize
		canon, err := jsoncanonicalizer.Transform(doc)
		if err != nil {
			log.Debugf("cannot canonicalize doc #%d in %s: %v", docIndex, path, err)
			continue
		}

		// Hash the canonical doc
		dsCan, hashErr := cryptoutil.CalculateDigestSetFromBytes(canon, ctx.Hashes())
		if hashErr != nil {
			log.Debugf("CalculateDigestSetFromBytes error doc #%d in %s: %v", docIndex, path, hashErr)
		}

		if hashErr == nil && len(dsCan) > 0 {
			canName := fmt.Sprintf("canonical-json:%s#doc%d", path, docIndex)
			a.subjectDigests[canName] = dsCan
			log.Debugf("Created subject %q for doc #%d in %s", canName, docIndex, path)

		}

		// Store the doc record
		a.Documents = append(a.Documents, DocumentRecord{
			FileName:        path,
			OriginalDigest:  origDigest,
			Canonical:       canon,
			CanonicalDigest: dsCan,
		})

		// If queries exist, run them
		var root interface{}
		if e := json.Unmarshal(canon, &root); e != nil {
			log.Debugf("json.Unmarshal error doc #%d in %s: %v", docIndex, path, e)
			continue
		}

		for subjName, jqExpr := range a.SubjectQueries {
			a.runOneJQ(path, docIndex, subjName, jqExpr, root, ctx)
		}
	}
	return nil
}

// runOneJQ applies a single jq expression to a doc, creating additional subject digests.
func (a *Attestor) runOneJQ(filePath string, docIndex int, subjectName, jqExpr string, root interface{}, ctx *attestation.AttestationContext) {
	q, err := gojq.Parse(jqExpr)
	if err != nil {
		log.Warnf("invalid jq expression %q for subject %q (file=%s docIndex=%d): %v",
			jqExpr, subjectName, filePath, docIndex, err)
		return
	}

	iter := q.Run(root)
	idx := 0
	for {
		v, ok := iter.Next()
		if !ok {
			break
		}
		if runtimeErr, isErr := v.(error); isErr {
			log.Debugf("jq runtime error for subject %q (file=%s docIndex=%d): %v",
				subjectName, filePath, docIndex, runtimeErr)
			continue
		}

		b, _ := json.Marshal(v)
		if string(b) == "null" {
			// skip null results
			continue
		}

		ds, e := cryptoutil.CalculateDigestSetFromBytes(b, ctx.Hashes())
		if e != nil || len(ds) == 0 {
			log.Debugf("digest error or empty subject for %q (file=%s docIndex=%d): %v",
				subjectName, filePath, docIndex, e)
			continue
		}

		subKey := fmt.Sprintf("%s:%s#doc%d#%d", filePath, subjectName, docIndex, idx)
		a.subjectDigests[subKey] = ds
		idx++
	}
}
