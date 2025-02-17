package policy_v2

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/interpreter"
	attestationv1 "github.com/in-toto/attestation/go/v1"
	witnessattestation "github.com/in-toto/go-witness/attestation"
	// attestors
	// _ "github.com/in-toto/go-witness/attestation/aws-iid"
	// _ "github.com/in-toto/go-witness/attestation/commandrun"
	// _ "github.com/in-toto/go-witness/attestation/environment"
	// _ "github.com/in-toto/go-witness/attestation/gcp-iit"
	// _ "github.com/in-toto/go-witness/attestation/git"
	// _ "github.com/in-toto/go-witness/attestation/github"
	// _ "github.com/in-toto/go-witness/attestation/gitlab"
	// _ "github.com/in-toto/go-witness/attestation/jwt"
	// _ "github.com/in-toto/go-witness/attestation/link"
	// _ "github.com/in-toto/go-witness/attestation/material"
	// _ "github.com/in-toto/go-witness/attestation/maven"
	// _ "github.com/in-toto/go-witness/attestation/oci"
	// _ "github.com/in-toto/go-witness/attestation/policyverify"
	// _ "github.com/in-toto/go-witness/attestation/product"
	// _ "github.com/in-toto/go-witness/attestation/sarif"
	// _ "github.com/in-toto/go-witness/attestation/sbom"
	// _ "github.com/in-toto/go-witness/attestation/slsa"
	// _ "github.com/in-toto/go-witness/attestation/vex"
)

// func Verify(layout *Layout, attestations map[string]*dsse.Envelope, parameters map[string]string) error {
// 	log.Info("Verifying layout expiry...")
// 	expiry, err := time.Parse(time.RFC3339, layout.Expires)
// 	if err != nil {
// 		return err
// 	}

// 	if compare := expiry.Compare(time.Now()); compare == -1 {
// 		return fmt.Errorf("layout has expired")
// 	}
// 	log.Info("Done.")

// 	if len(parameters) > 0 {
// 		log.Info("Substituting parameters...")
// 		layout, err = SubstituteParameters(layout, parameters)
// 		if err != nil {
// 			return err
// 		}
// 		log.Info("Done.")
// 	}

// 	log.Info("Fetching verifiers...")
// 	verifiers, err := GetEnvelopeVerifiers(layout.Functionaries)
// 	if err != nil {
// 		return err
// 	}
// 	envVerifier, err := dsse.NewEnvelopeVerifier(verifiers...)
// 	if err != nil {
// 		return err
// 	}
// 	log.Info("Done.")

// 	log.Info("Loading attestations as claims...")
// 	claims := map[string]map[string]*attestationv1.Statement{}
// 	for attestationName, env := range attestations {
// 		log.Infof("Loading %s...", attestationName)

// 		stepName := GetStepName(attestationName)
// 		if claims[stepName] == nil {
// 			claims[stepName] = map[string]*attestationv1.Statement{}
// 		}

// 		acceptedKeys, err := envVerifier.Verify(context.Background(), env)
// 		if err != nil {
// 			// The verifier loads all attestations and verifies their
// 			// signatures. It represents their claims in the format "<signer>
// 			// says <claim> for <step>", allowing policy to be written as "does
// 			// one of <trusted signers> say <claim> for <step>?"
// 			// While this might result in verifying the signatures of
// 			// attestations that aren't required for the specific layout, it
// 			// more cleanly separates policy evaluation from claim expression.
// 			// Also, we do not authenticate attestations from unknown verifiers,
// 			// as the keys used to verify the attestation signatures are taken
// 			// from the layout.  If we encounter an attestation signed by an
// 			// unrecognized key, the verifier logs this and moves on. This
// 			// attestation is not considered for further verification.
// 			log.Infof("Unable to verify %s's signatures", attestationName)
// 			continue
// 		}

// 		log.Infof("Verified signature for %s", attestationName)

// 		sb, err := env.DecodeB64Payload()
// 		if err != nil {
// 			return fmt.Errorf("unable to decode base64-encoded payload: %w", err)
// 		}

// 		statement := &attestationv1.Statement{}
// 		if err := protojson.Unmarshal(sb, statement); err != nil {
// 			return fmt.Errorf("unable to load statement payload: %w", err)
// 		}

// 		for _, ak := range acceptedKeys {
// 			claims[stepName][ak.KeyID] = statement
// 		}
// 	}
// 	log.Info("Done.")

// 	env, err := GetCELEnv()
// 	if err != nil {
// 		return err
// 	}

// 	for _, step := range layout.Steps {
// 		stepStatements, ok := claims[step.Name]
// 		if !ok {
// 			return fmt.Errorf("no claims found for step %s", step.Name)
// 		}

// 		if step.Threshold == 0 {
// 			step.Threshold = 1
// 		}

// 		trustedStatements := GetPredicates(stepStatements, step.Functionaries)
// 		if len(trustedStatements) < step.Threshold {
// 			return fmt.Errorf("threshold not met for step %s", step.Name)
// 		}

// 		// TODO: reduce statements if they're identical to avoid checking all of
// 		// them
// 		// See in-toto 1.0

// 		acceptedPredicates := 0
// 		failedChecks := []error{}
// 		for functionary, statement := range trustedStatements {
// 			log.Infof("Verifying claim for step '%s' of type '%s' by '%s'...", step.Name, step.ExpectedPredicateType, functionary)
// 			failed := false

// 			// Check the predicate type matches the expected value in the layout
// 			if step.ExpectedPredicateType != statement.PredicateType {
// 				failed = true
// 				failedChecks = append(failedChecks, fmt.Errorf("for step %s, statement with unexpected predicate type %s found", step.Name, statement.PredicateType))
// 			}

// 			// Check materials and products
// 			if err := ApplyArtifactRules(statement, step.ExpectedMaterials, step.ExpectedProducts, claims); err != nil {
// 				failed = true
// 				failedChecks = append(failedChecks, fmt.Errorf("for step %s, claim by %s failed artifact rules: %w", step.Name, functionary, err))
// 			}

// 			input, err := GetActivation(statement)
// 			if err != nil {
// 				return err
// 			}

// 			// Check attribute rules
// 			if err := ApplyAttributeRules(env, input, step.ExpectedAttributes); err != nil {
// 				failed = true
// 				failedChecks = append(failedChecks, fmt.Errorf("for step %s, claim by %s failed attribute rules: %w", step.Name, functionary, err))
// 			}

// 			// Examine collector claims in attestation collection
// 			if step.ExpectedPredicateType == witnessattestation.CollectionType {
// 				log.Infof("Verifying attestors for collection of step '%s'", step.Name)
// 				collectionBytes, err := json.Marshal(statement.Predicate)
// 				if err != nil {
// 					return err
// 				}

// 				collection := &witnessattestation.Collection{}
// 				if err := json.Unmarshal(collectionBytes, collection); err != nil {
// 					return err
// 				}
// 				log.Infof("Unmarshaled collection for step '%s'", step.Name)

// 				// TODO: assumes only one of each attestor type
// 				subAttestors := make(map[string]witnessattestation.CollectionAttestation, len(collection.Attestations))
// 				for _, subAttestor := range collection.Attestations {
// 					subAttestors[subAttestor.Type] = subAttestor
// 				}

// 				env, err := GetCollectionCELEnv()
// 				if err != nil {
// 					return err
// 				}

// 				for _, attestorConstraint := range step.ExpectedAttestors {
// 					attestor, ok := subAttestors[attestorConstraint.AttestorType]
// 					if !ok {
// 						failed = true
// 						failedChecks = append(failedChecks, fmt.Errorf("for step %s, attestor of type %s not found in collection", step.Name, attestorConstraint.AttestorType))
// 						continue
// 					}

// 					input, err := GetCollectionActivation(&attestor)
// 					if err != nil {
// 						return err
// 					}

// 					if err := ApplyAttributeRules(env, input, attestorConstraint.ExpectedAttributes); err != nil {
// 						failed = true
// 						failedChecks = append(failedChecks, fmt.Errorf("for step %s, claim by %s failed attribute rules for attestor %s: %w", step.Name, functionary, attestorConstraint.AttestorType, err))
// 					}
// 				}
// 			}

// 			if failed {
// 				log.Infof("Claim for step %s of type %s by %s failed.", step.Name, step.ExpectedPredicateType, functionary)
// 			} else {
// 				acceptedPredicates += 1
// 				log.Info("Done.")
// 			}
// 		}
// 		if acceptedPredicates < step.Threshold {
// 			return errors.Join(failedChecks...)
// 		}
// 	}

// 	log.Info("Verification successful!")

// 	return nil
// }

// func GetEnvelopeVerifiers(publicKeys map[string]Functionary) ([]dsse.Verifier, error) {
// 	verifiers := []dsse.Verifier{}

// 	for _, key := range publicKeys {
// 		log.Infof("Creating verifier for key %s", key.KeyID)
// 		sslibKey := &signerverifier.SSLibKey{
// 			KeyIDHashAlgorithms: key.KeyIDHashAlgorithms,
// 			KeyType:             key.KeyType,
// 			KeyVal: signerverifier.KeyVal{
// 				Public: key.KeyVal.Public,
// 			},
// 			Scheme: key.Scheme,
// 			KeyID:  key.KeyID,
// 		}

// 		switch key.KeyType { // TODO: use scheme
// 		case "rsa":
// 			verifier, err := signerverifier.NewRSAPSSSignerVerifierFromSSLibKey(sslibKey)
// 			if err != nil {
// 				return nil, err
// 			}

// 			verifiers = append(verifiers, verifier)
// 		case "ecdsa":
// 			verifier, err := signerverifier.NewECDSASignerVerifierFromSSLibKey(sslibKey)
// 			if err != nil {
// 				return nil, err
// 			}

// 			verifiers = append(verifiers, verifier)
// 		case "ed25519":
// 			verifier, err := signerverifier.NewED25519SignerVerifierFromSSLibKey(sslibKey)
// 			if err != nil {
// 				return nil, err
// 			}

// 			verifiers = append(verifiers, verifier)
// 		}
// 	}

// 	return verifiers, nil
// }

func GetPredicates(statements map[string]*attestationv1.Statement, functionaries []string) map[string]*attestationv1.Statement {
	matchedPredicates := map[string]*attestationv1.Statement{}

	for _, keyID := range functionaries {
		statement, ok := statements[keyID]
		if ok {
			matchedPredicates[keyID] = statement
		}
	}

	return matchedPredicates
}

func GetCELEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Types(&attestationv1.Statement{}),
		cel.Variable("subject", cel.ListType(cel.ObjectType("in_toto_attestation.v1.ResourceDescriptor"))),
		cel.Variable("predicateType", cel.StringType),
		cel.Variable("predicate", cel.ObjectType("google.protobuf.Struct")),
	)
}

func GetCollectionCELEnv() (*cel.Env, error) {
	return cel.NewEnv(
		// cel.Variable("type", cel.StringType),
		cel.Variable("attestation", cel.ObjectType("google.protobuf.Struct")),
		cel.Variable("startTime", cel.TimestampType),
		cel.Variable("endTime", cel.TimestampType),
	)
}

func GetActivation(statement *attestationv1.Statement) (interpreter.Activation, error) {
	return interpreter.NewActivation(map[string]any{
		"type":          statement.Type,
		"subject":       statement.Subject,
		"predicateType": statement.PredicateType,
		"predicate":     statement.Predicate,
	})
}

func GetCollectionActivation(collection *witnessattestation.CollectionAttestation) (interpreter.Activation, error) {
	attestationBytes, err := json.Marshal(collection.Attestation)
	if err != nil {
		return nil, err
	}
	attestation := map[string]any{}
	if err := json.Unmarshal(attestationBytes, &attestation); err != nil {
		return nil, err
	}

	return interpreter.NewActivation(map[string]any{
		"attestation": attestation,
		"startTime":   collection.StartTime,
		"endTime":     collection.EndTime,
	})
}

func GetStepName(name string) string {
	nameS := strings.Split(name, ".")
	nameS = nameS[:len(nameS)-1]
	return strings.Join(nameS, ".")
}

func SubstituteParameters(layout *Layout, parameters map[string]string) (*Layout, error) {
	replacementDirectives := make([]string, 0, 2*len(parameters))
	re := regexp.MustCompile("^[a-zA-Z0-9_-]+$")

	for parameter, value := range parameters {
		if ok := re.MatchString(parameter); !ok {
			return nil, fmt.Errorf("invalid parameter format")
		}

		parameterVar := fmt.Sprintf("{%s}", parameter)
		if strings.Contains(value, parameterVar) {
			return nil, fmt.Errorf("parameter's value refers to itself")
		}

		replacementDirectives = append(replacementDirectives, parameterVar)
		replacementDirectives = append(replacementDirectives, value)
	}

	replacer := strings.NewReplacer(replacementDirectives...)

	for _, step := range layout.Steps {
		for i, materialRule := range step.ExpectedMaterials {
			step.ExpectedMaterials[i] = Replace(replacer, materialRule)
		}

		for i, productRule := range step.ExpectedProducts {
			step.ExpectedProducts[i] = Replace(replacer, productRule)
		}

		for i, attributeRule := range step.ExpectedAttributes {
			step.ExpectedAttributes[i] = Constraint{
				Rule:           Replace(replacer, attributeRule.Rule),
				AllowIfNoClaim: attributeRule.AllowIfNoClaim,
				Warn:           attributeRule.Warn,
				Debug:          Replace(replacer, attributeRule.Debug),
			}
		}

		for _, attestorConstraint := range step.ExpectedAttestors {
			for j, attributeRule := range attestorConstraint.ExpectedAttributes {
				attestorConstraint.ExpectedAttributes[j] = Constraint{
					Rule:           Replace(replacer, attributeRule.Rule),
					AllowIfNoClaim: attributeRule.AllowIfNoClaim,
					Warn:           attributeRule.Warn,
					Debug:          Replace(replacer, attributeRule.Debug),
				}
			}
		}
	}

	return layout, nil
}

func Replace(replacer *strings.Replacer, input string) string {
	var output string
	for {
		// repeat to catch embedded paramsub directives
		output = replacer.Replace(input)
		if output == input {
			break
		}

		input = output
	}

	return output
}
