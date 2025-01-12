package jsonattestor

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/ghodss/yaml"
	"github.com/itchyny/gojq"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/registry"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "json"
	Type    = "https://witness.dev/attestations/json/v0.1"
	RunType = attestation.PostProductRunType
)

// Attestor processes a JSON/YAML file, storing canonical JSON and user queries.
type Attestor struct {
	CanonicalJSON  []byte
	SubjectQueries map[string]string
	subjects       map[string]cryptoutil.DigestSet
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

func New() *Attestor {
	return &Attestor{
		subjects:       make(map[string]cryptoutil.DigestSet),
		SubjectQueries: make(map[string]string),
	}
}

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
		if len(parts) != 2 {
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

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) Type() string {
	return Type
}

func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(a)
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	prods := ctx.Products()
	if len(prods) == 0 {
		return errors.New("no products to attest")
	}
	path := pickOneJSONFile(prods)
	if path == "" {
		return errors.New("no .json or .yaml/.yml file found among products")
	}
	fullPath := filepath.Join(ctx.WorkingDir(), path)
	orig, err := os.ReadFile(fullPath)
	if err != nil {
		return fmt.Errorf("read error: %w", err)
	}

	// original-file subject
	dsOrig, err := cryptoutil.CalculateDigestSetFromBytes(orig, ctx.Hashes())
	if err == nil && len(dsOrig) > 0 {
		a.subjects["original-file"] = dsOrig
	}

	maybeJSON, e := yaml.YAMLToJSON(orig)
	if e != nil {
		maybeJSON = orig
	}
	var any interface{}
	if e := json.Unmarshal(maybeJSON, &any); e != nil {
		return fmt.Errorf("invalid JSON/YAML: %w", e)
	}

	a.CanonicalJSON, err = jsoncanonicalizer.Transform(maybeJSON)
	if err != nil {
		return fmt.Errorf("canonicalization error: %w", err)
	}
	if dsCan, e := cryptoutil.CalculateDigestSetFromBytes(a.CanonicalJSON, ctx.Hashes()); e == nil && len(dsCan) > 0 {
		a.subjects["canonical-json"] = dsCan
	}

	var root interface{}
	if e := json.Unmarshal(a.CanonicalJSON, &root); e != nil {
		return fmt.Errorf("re-unmarshal canonical JSON: %w", e)
	}
	for subjName, jqExpr := range a.SubjectQueries {
		runOneJQ(a.subjects, subjName, jqExpr, root, ctx)
	}
	return nil
}

func pickOneJSONFile(prods map[string]attestation.Product) string {
	for p := range prods {
		ext := strings.ToLower(filepath.Ext(p))
		if ext == ".json" || ext == ".yaml" || ext == ".yml" {
			return p
		}
	}
	return ""
}

func runOneJQ(
	subjects map[string]cryptoutil.DigestSet,
	subjectName string,
	jqExpr string,
	root interface{},
	ctx *attestation.AttestationContext,
) {
	q, err := gojq.Parse(jqExpr)
	if err != nil {
		log.Debugf("invalid jq %q for subject %q: %v", jqExpr, subjectName, err)
		return
	}
	iter := q.Run(root)
	idx := 0
	for {
		v, ok := iter.Next()
		if !ok {
			break
		}
		if e, isErr := v.(error); isErr {
			log.Debugf("jq runtime error for subject %q: %v", subjectName, e)
			continue
		}
		b, _ := json.Marshal(v)
		if string(b) == "null" {
			continue
		}
		ds, e := cryptoutil.CalculateDigestSetFromBytes(b, ctx.Hashes())
		if e != nil || len(ds) == 0 {
			log.Debugf("digest error or empty for subject %q: %v", subjectName, e)
			continue
		}
		n := fmt.Sprintf("%s#%d", subjectName, idx) // ALWAYS include #i
		subjects[n] = ds
		idx++
	}
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	return a.subjects
}
