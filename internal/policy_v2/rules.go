package policy_v2

import (
	"encoding/json"
	"fmt"
	"path"
	"reflect"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/interpreter"
	linkPredicatev0 "github.com/in-toto/attestation/go/predicates/link/v0"
	provenancePredicatev1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	attestationv1 "github.com/in-toto/attestation/go/v1"
	witnessattestation "github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/in-toto-golang/in_toto"
	provenancePredicatev02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
)

func ApplyArtifactRules(statement *attestationv1.Statement, materialRules []string, productRules []string, claims map[string]map[string]*attestationv1.Statement) error {
	materialsList, productsList, err := GetMaterialsAndProducts(statement)
	if err != nil {
		return err
	}

	materials := map[string]*attestationv1.ResourceDescriptor{}
	materialsPaths := in_toto.NewSet()
	for _, artifact := range materialsList {
		artifact := artifact
		materials[artifact.Name] = artifact
		materialsPaths.Add(path.Clean(artifact.Name))
	}

	products := map[string]*attestationv1.ResourceDescriptor{}
	productsPaths := in_toto.NewSet()
	for _, artifact := range productsList {
		artifact := artifact
		products[artifact.Name] = artifact
		productsPaths.Add(path.Clean(artifact.Name))
	}

	created := productsPaths.Difference(materialsPaths)
	deleted := materialsPaths.Difference(productsPaths)
	remained := materialsPaths.Intersection(productsPaths)
	modified := in_toto.NewSet()
	for name := range remained {
		if !reflect.DeepEqual(materials[name].Digest, products[name].Digest) {
			modified.Add(name)
		}
	}

	log.Infof("Applying material rules...")
	for _, r := range materialRules {
		log.Infof("Evaluating rule `%s`...", r)
		rule, err := in_toto.UnpackRule(strings.Split(r, " "))
		if err != nil {
			return err
		}

		filtered := materialsPaths.Filter(path.Clean(rule["pattern"]))
		var consumed in_toto.Set
		switch rule["type"] {
		case "match":
			consumed = ApplyMatchRule(rule, materials, materialsPaths, claims)
		case "allow":
			consumed = filtered
		case "delete":
			consumed = filtered.Intersection(deleted)
		case "disallow":
			if len(filtered) > 0 {
				return fmt.Errorf("materials verification failed: %s disallowed by rule %s", filtered.Slice(), rule)
			}
		case "require":
			if !materialsPaths.Has(rule["pattern"]) {
				return fmt.Errorf("materials verification failed: %s required but not found", rule["pattern"])
			}
		default:
			return fmt.Errorf("invalid material rule %s", rule["type"])
		}
		materialsPaths = materialsPaths.Difference(consumed)
	}

	// adityasaky: I've separated these out on purpose right now
	log.Infof("Applying product rules...")
	for _, r := range productRules {
		log.Infof("Evaluating rule `%s`...", r)
		rule, err := in_toto.UnpackRule(strings.Split(r, " "))
		if err != nil {
			return err
		}

		filtered := productsPaths.Filter(path.Clean(rule["pattern"]))
		var consumed in_toto.Set
		switch rule["type"] {
		case "match":
			consumed = ApplyMatchRule(rule, products, productsPaths, claims)
		case "allow":
			consumed = filtered
		case "create":
			consumed = filtered.Intersection(created)
		case "modify":
			consumed = filtered.Intersection(modified)
		case "disallow":
			if len(filtered) > 0 {
				return fmt.Errorf("products verification failed: %s disallowed by rule %s", filtered.Slice(), rule)
			}
		case "require":
			if !productsPaths.Has(rule["pattern"]) {
				return fmt.Errorf("products verification failed: %s required but not found", rule["pattern"])
			}
		default:
			return fmt.Errorf("invalid product rule %s", rule["type"])
		}
		productsPaths = productsPaths.Difference(consumed)
	}

	return nil
}

func ApplyAttributeRules(env *cel.Env, input interpreter.Activation, rules []Constraint) error {
	log.Infof("Applying attribute rules...")
	for _, r := range rules {
		log.Infof("Evaluating rule `%s`...", r.Rule)
		ast, issues := env.Compile(r.Rule)
		if issues != nil && issues.Err() != nil {
			return issues.Err()
		}

		prog, err := env.Program(ast)
		if err != nil {
			return err
		}

		out, _, err := prog.Eval(input)
		if err != nil {
			if strings.Contains(err.Error(), "no such attribute") || strings.Contains(err.Error(), "no such key") && r.AllowIfNoClaim {
				continue
			}
			return err
		}
		switch result := out.Value().(type) {
		case bool:
			if !result {
				var message string
				if r.Debug == "" {
					message = fmt.Sprintf("verification failed for rule '%s'", r.Rule)
				} else {
					message = fmt.Sprintf("%s\nin rule '%s'", r.Debug, r.Rule)
				}

				if !r.Warn {
					return fmt.Errorf("%s", message)
				}

				log.Warnf("%s", message)
			}
		case error:
			log.Info(result)
			return fmt.Errorf("CEL error: %w", result)
		}
	}

	return nil
}

func GetMaterialsAndProducts(statement *attestationv1.Statement) ([]*attestationv1.ResourceDescriptor, []*attestationv1.ResourceDescriptor, error) {
	switch statement.PredicateType {
	case "https://in-toto.io/attestation/link/v0.3":
		linkBytes, err := json.Marshal(statement.Predicate)
		if err != nil {
			return nil, nil, err
		}

		link := &linkPredicatev0.Link{}
		if err := protojson.Unmarshal(linkBytes, link); err != nil {
			return nil, nil, err
		}

		return link.Materials, statement.Subject, nil

	case "https://slsa.dev/provenance/v1":
		provenanceBytes, err := json.Marshal(statement.Predicate)
		if err != nil {
			return nil, nil, err
		}

		provenance := &provenancePredicatev1.Provenance{}
		if err := protojson.Unmarshal(provenanceBytes, provenance); err != nil {
			return nil, nil, err
		}

		return provenance.BuildDefinition.ResolvedDependencies, statement.Subject, nil

	case "https://slsa.dev/provenance/v0.2":
		// TODO: assumes provenance v0.2 is in statement v1

		provenanceBytes, err := json.Marshal(statement.Predicate)
		if err != nil {
			return nil, nil, err
		}

		provenance := &provenancePredicatev02.ProvenancePredicate{}
		if err := json.Unmarshal(provenanceBytes, provenance); err != nil {
			return nil, nil, err
		}

		materials := []*attestationv1.ResourceDescriptor{}
		for _, material := range provenance.Materials {
			materials = append(materials, &attestationv1.ResourceDescriptor{
				Name:   material.URI, // TODO: figure this out
				Uri:    material.URI,
				Digest: material.Digest,
			})
		}

		return materials, statement.Subject, nil

	case witnessattestation.CollectionType:
		collectionBytes, err := json.Marshal(statement.Predicate)
		if err != nil {
			return nil, nil, err
		}

		collection := &witnessattestation.Collection{}
		if err := json.Unmarshal(collectionBytes, collection); err != nil {
			return nil, nil, err
		}

		collectionMaterials := collection.Materials()
		materials := make([]*attestationv1.ResourceDescriptor, 0, len(collectionMaterials))
		for name, digestObj := range collectionMaterials {
			digest, err := digestObj.ToNameMap()
			if err != nil {
				return nil, nil, err
			}
			materials = append(materials, &attestationv1.ResourceDescriptor{
				Name:   name,
				Digest: digest,
			})
		}

		collectionProducts := collection.Subjects()
		products := make([]*attestationv1.ResourceDescriptor, 0, len(collectionProducts))
		for name, digestObj := range collectionProducts {
			digest, err := digestObj.ToNameMap()
			if err != nil {
				return nil, nil, err
			}
			products = append(products, &attestationv1.ResourceDescriptor{
				Name:   name,
				Digest: digest,
			})
		}

		return materials, products, nil

	default:
		return statement.Subject, nil, nil
	}
}

func ApplyMatchRule(rule map[string]string, srcArtifacts map[string]*attestationv1.ResourceDescriptor, queue in_toto.Set, claims map[string]map[string]*attestationv1.Statement) in_toto.Set {
	consumed := in_toto.NewSet()

	dstClaims, ok := claims[rule["dstName"]]
	if !ok {
		return consumed
	}

	dstMaterials, dstProducts, err := GetDestinationArtifacts(dstClaims)
	if err != nil {
		// FIXME: what is the right behaviour here across claims?
		return consumed
	}

	var dstArtifacts map[string]*attestationv1.ResourceDescriptor
	if rule["dstType"] == "materials" {
		dstArtifacts = dstMaterials
	} else {
		dstArtifacts = dstProducts
	}

	if rule["pattern"] != "" {
		rule["pattern"] = path.Clean(rule["pattern"])
	}

	for p := range srcArtifacts {
		if path.Clean(p) != p {
			srcArtifacts[path.Clean(p)] = srcArtifacts[p]
			delete(srcArtifacts, p)
		}
	}

	for p := range dstArtifacts {
		if path.Clean(p) != p {
			dstArtifacts[path.Clean(p)] = dstArtifacts[p]
			delete(dstArtifacts, p)
		}
	}

	for _, prefix := range []string{"srcPrefix", "dstPrefix"} {
		if rule[prefix] != "" {
			rule[prefix] = path.Clean(rule[prefix])
			if !strings.HasSuffix(rule[prefix], "/") {
				rule[prefix] += "/"
			}
		}
	}

	for srcPath := range queue {
		srcBasePath := strings.TrimPrefix(srcPath, rule["srcPrefix"])

		// Ignore artifacts not matched by rule pattern
		matched, err := match(rule["pattern"], srcBasePath)
		if err != nil || !matched {
			continue
		}

		// Construct corresponding destination artifact path, i.e.
		// an optional destination prefix plus the source base path
		dstPath := path.Clean(path.Join(rule["dstPrefix"], srcBasePath))

		// Try to find the corresponding destination artifact
		dstArtifact, exists := dstArtifacts[dstPath]
		// Ignore artifacts without corresponding destination artifact
		if !exists {
			continue
		}

		// Ignore artifact pairs with no matching hashes
		if !reflect.DeepEqual(srcArtifacts[srcPath].Digest, dstArtifact.Digest) {
			continue
		}

		// Only if a source and destination artifact pair was found and
		// their hashes are equal, will we mark the source artifact as
		// successfully consumed, i.e. it will be removed from the queue
		consumed.Add(srcPath)
	}

	return consumed
}

func GetDestinationArtifacts(dstClaims map[string]*attestationv1.Statement) (map[string]*attestationv1.ResourceDescriptor, map[string]*attestationv1.ResourceDescriptor, error) {
	materials := map[string]*attestationv1.ResourceDescriptor{}
	products := map[string]*attestationv1.ResourceDescriptor{}

	for _, claim := range dstClaims {
		materialsList, productsList, err := GetMaterialsAndProducts(claim)
		if err != nil {
			return nil, nil, err
		}

		// FIXME: we're overwriting artifact info without checking if claims agree

		for _, artifact := range materialsList {
			artifact := artifact
			materials[artifact.Name] = artifact
		}

		for _, artifact := range productsList {
			artifact := artifact
			products[artifact.Name] = artifact
		}
	}

	return materials, products, nil
}
