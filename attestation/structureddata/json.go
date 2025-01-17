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

const (
	// Name is the short name for this attestor.
	Name = "structureddata"

	// Type is the formal type URI for this attestor.
	Type = "https://witness.dev/attestations/structureddata/v0.1"

	// RunType indicates when this attestor runs in the pipeline.
	RunType = attestation.PostProductRunType
)

// DocumentRecord represents one canonicalized document from a file.
type DocumentRecord struct {
	// FileName is the product file from which this document came.
	FileName string `json:"filename"`

	// OriginalDigest holds the digest(s) of the entire file, e.g. sha256.
	OriginalDigest cryptoutil.DigestSet `json:"originalDigest"`

	// Canonical is the canonical JSON for this document, stored as raw bytes
	// so Rego or other tools can parse it directly without double-encoding.
	Canonical json.RawMessage `json:"canonical"`
}

// Attestor processes multiple JSON/YAML files and stores their canonical forms.
// If the YAML has multiple documents in one file, we store each doc separately.
type Attestor struct {
	// Documents holds the canonical doc records for *all* files processed.
	Documents []DocumentRecord `json:"documents"`

	// SubjectQueries is a map of user-defined subjectName => jq expression
	// for generating extra subject digests from the canonical form.
	SubjectQueries map[string]string `json:"subjectqueries,omitempty"`

	// internal map for computed digests (including queries)
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

// New returns an Attestor with empty slices/maps.
func New() *Attestor {
	return &Attestor{
		Documents:      []DocumentRecord{},
		SubjectQueries: make(map[string]string),
		subjectDigests: make(map[string]cryptoutil.DigestSet),
	}
}

// ParseSubjectQueries handles user-supplied "subjectName=jqExpr" pairs.
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
		// Switch to SplitN if you want to allow '=' inside the jq expression
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid subject-queries pair %q (missing '=')", pair)
		}
		name := strings.TrimSpace(parts[0])
		expr := strings.TrimSpace(parts[1])
		if name == "" || expr == "" {
			return nil, fmt.Errorf("invalid subject-queries pair %q (empty name or expression)", pair)
		}
		// If a user repeats the same name, we'll let the last definition "win"
		out[name] = expr
	}
	return out, nil
}

// Name returns the short name.
func (a *Attestor) Name() string {
	return Name
}

// Type returns the URI type.
func (a *Attestor) Type() string {
	return Type
}

// RunType indicates when this attestor is used.
func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

// Schema returns the JSON Schema for this attestor.
func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(a)
}

// Attest processes each JSON/YAML product found. If none is found, it returns an error.
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
				// Log the error, continue to next file
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

// handleFile reads the file, calculates original digest, then attempts
// to parse YAML→JSON, canonicalize, store doc records, and run queries.
func (a *Attestor) handleFile(ctx *attestation.AttestationContext, path string) error {
	fullPath := filepath.Join(ctx.WorkingDir(), path)
	content, err := os.ReadFile(fullPath)
	if err != nil {
		return fmt.Errorf("could not read file %s: %w", path, err)
	}

	// Always compute & store original file digest, even if we fail on canonicalizing
	origDigest, err := cryptoutil.CalculateDigestSetFromBytes(content, ctx.Hashes())
	if err != nil || len(origDigest) == 0 {
		log.Debugf("unable to compute digest for original file %s: %v", path, err)
	} else {
		// Example subject name: "original-file:<path>"
		subName := fmt.Sprintf("original-file:%s", path)
		a.subjectDigests[subName] = origDigest
	}

	// Attempt to parse multiple YAML documents from the same file
	docs, err := splitYAMLDocs(content)
	if err != nil {
		return fmt.Errorf("splitting YAML docs: %w", err)
	}
	if len(docs) == 0 {
		return fmt.Errorf("no valid YAML/JSON documents found in %s", path)
	}

	for docIndex, doc := range docs {
		// doc is a single YAML/JSON doc
		canon, err := jsoncanonicalizer.Transform(doc)
		if err != nil {
			// skip this doc, log error
			log.Debugf("cannot canonicalize doc #%d in %s: %v", docIndex, path, err)
			continue
		}

		// store the doc record
		record := DocumentRecord{
			FileName:       path,
			OriginalDigest: origDigest,
			Canonical:      canon,
		}
		a.Documents = append(a.Documents, record)

		// Also store the canonical doc's digest
		dsCan, e := cryptoutil.CalculateDigestSetFromBytes(canon, ctx.Hashes())
		if e == nil && len(dsCan) > 0 {
			subName := fmt.Sprintf("canonical-json:%s#doc%d", path, docIndex)
			a.subjectDigests[subName] = dsCan
		} else {
			log.Debugf("could not compute canonical doc digest for doc #%d in %s: %v", docIndex, path, e)
		}

		// run subject queries on that canonical doc
		var root interface{}
		if e := json.Unmarshal(canon, &root); e != nil {
			log.Debugf("could not re-unmarshal canonical doc #%d in %s: %v", docIndex, path, e)
			continue
		}
		// For each query, parse & run. If parse fails, we warn but move on to next query.
		for subjName, jqExpr := range a.SubjectQueries {
			a.runOneJQ(path, docIndex, subjName, jqExpr, root, ctx)
		}
	}
	return nil
}

// runOneJQ runs one jq expression on the doc root, storing additional subject digests.
// We do not return early if there's a parse error or runtime error—we keep going for
// each query & each doc.
func (a *Attestor) runOneJQ(filePath string, docIndex int, subjectName, jqExpr string, root interface{}, ctx *attestation.AttestationContext) {
	q, err := gojq.Parse(jqExpr)
	if err != nil {
		// We log a warning (or debug) but do not return => keep trying other queries
		log.Warnf("invalid jq expression %q for subject %q (file=%s docIndex=%d): %v", jqExpr, subjectName, filePath, docIndex, err)
		return
	}

	iter := q.Run(root)
	idx := 0
	for {
		v, ok := iter.Next()
		if !ok {
			break // done
		}
		if e, isErr := v.(error); isErr {
			log.Debugf("jq runtime error for subject %q (file=%s docIndex=%d) : %v", subjectName, filePath, docIndex, e)
			continue
		}

		b, _ := json.Marshal(v)
		if string(b) == "null" {
			// no subject derived
			log.Debugf("jq query result is null, skipping. subject=%q file=%s docIndex=%d", subjectName, filePath, docIndex)
			continue
		}

		ds, e := cryptoutil.CalculateDigestSetFromBytes(b, ctx.Hashes())
		if e != nil || len(ds) == 0 {
			log.Debugf("digest error or empty subject for %q (file=%s docIndex=%d): %v", subjectName, filePath, docIndex, e)
			continue
		}

		// subKey includes doc index + iteration index
		subKey := fmt.Sprintf("%s:%s#doc%d#%d", filePath, subjectName, docIndex, idx)
		a.subjectDigests[subKey] = ds
		idx++
	}
}

// Subjects returns all known subject digests from this attestor.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	return a.subjectDigests
}

// isJSONorYAML returns true if the file extension is .json or .yaml/.yml
func isJSONorYAML(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".json" || ext == ".yaml" || ext == ".yml"
}

// splitYAMLDocs decodes multiple YAML documents (or JSON) into separate JSON byte slices.
// If the content is valid JSON but not valid YAML, we treat the entire file as one doc.
func splitYAMLDocs(content []byte) ([][]byte, error) {
	var out [][]byte

	// Use YAML's decoder to handle multiple documents
	dec := yaml.NewDecoder(strings.NewReader(string(content)))
	for {
		var raw interface{}
		err := dec.Decode(&raw)
		if err != nil {
			// If EOF or an empty doc, break
			if strings.Contains(strings.ToLower(err.Error()), "eof") ||
				strings.Contains(strings.ToLower(err.Error()), "document is empty") {
				break
			}
			// Otherwise, just log and continue to next doc
			log.Debugf("error decoding YAML doc: %v", err)
			continue
		}

		// Marshal each doc as JSON
		j, err := json.Marshal(raw)
		if err != nil {
			log.Debugf("could not marshal YAML doc to JSON: %v", err)
			continue
		}
		out = append(out, j)
	}

	// If we didn't parse any doc, maybe it's raw JSON
	if len(out) == 0 {
		if json.Valid(content) {
			out = append(out, content)
		}
	}

	return out, nil
}
