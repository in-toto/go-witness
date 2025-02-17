package policy_v2

import (
	"os"

	"gopkg.in/yaml.v3"
)

// copied from go-sslib to use yaml tags
type Functionary struct {
	KeyIDHashAlgorithms []string `yaml:"keyIDHashAlgorithms"`
	KeyType             string   `yaml:"keyType"`
	KeyVal              KeyVal   `yaml:"keyVal"`
	Scheme              string   `yaml:"scheme"`
	KeyID               string   `yaml:"keyID"`
}

type KeyVal struct {
	Public string `yaml:"public"`
}

type Constraint struct {
	Rule           string `yaml:"rule"`
	AllowIfNoClaim bool   `yaml:"allowIfNoClaim"`
	Warn           bool   `yaml:"warn"`
	Debug          string `yaml:"debug"`
}

type ExpectedAttestorConstraints struct {
	AttestorType       string       `yaml:"attestorType"`
	ExpectedAttributes []Constraint `yaml:"expectedAttributes"`
}

type Step struct {
	Name                  string                        `yaml:"name"`
	Functionaries         []string                      `yaml:"functionaries"`
	Threshold             int                           `yaml:"threshold"`
	ExpectedPredicateType string                        `yaml:"expectedPredicateType"`
	ExpectedMaterials     []string                      `yaml:"expectedMaterials"`
	ExpectedProducts      []string                      `yaml:"expectedProducts"`
	ExpectedAttributes    []Constraint                  `yaml:"expectedAttributes"`
	ExpectedAttestors     []ExpectedAttestorConstraints `yaml:"expectedAttestors"`
}

type ExpectedSubjectPredicates struct {
	PredicateType      string       `yaml:"predicateType"`
	ExpectedAttributes []Constraint `yaml:"expectedAttributes"`
	Functionaries      []string     `yaml:"functionaries"`
	Threshold          int          `yaml:"threshold"`
}

type Subject struct {
	Subject            []string                    `yaml:"subject"`
	ExpectedPredicates []ExpectedSubjectPredicates `yaml:"expectedPredicates"`
}

type Inspection struct {
	Name               string       `yaml:"name"`
	Command            string       `yaml:"command"`
	Predicates         []string     `yaml:"predicates"`
	ExpectedMaterials  []string     `yaml:"expectedMaterials"`
	ExpectedProducts   []string     `yaml:"expectedProducts"`
	ExpectedAttributes []Constraint `yaml:"expectedAttributes"`
}

type Layout struct {
	Expires       string                 `yaml:"expires"`
	Functionaries map[string]Functionary `yaml:"functionaries"`
	Steps         []*Step                `yaml:"steps"`
	Subjects      []*Subject             `yaml:"subjects"`
	Inspections   []*Inspection          `yaml:"inspections"`
}

func LoadLayout(path string) (*Layout, error) {
	layoutBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	layout := &Layout{}
	if err := yaml.Unmarshal(layoutBytes, layout); err != nil {
		return nil, err
	}

	return layout, nil
}

type AttestationIdentifier struct {
	Functionary string
}
