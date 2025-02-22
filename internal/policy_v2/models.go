package policy_v2

import (
	"os"

	"github.com/in-toto/go-witness/dsse"
	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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

type PolicyV2 struct {
	Expires       metav1.Time                 `yaml:"expires"`
	Functionaries map[string]dsse.Functionary `yaml:"functionaries"`
	Steps         []*Step                     `yaml:"steps"`
	Subjects      []*Subject                  `yaml:"subjects"`
	Inspections   []*Inspection               `yaml:"inspections"`
}

func LoadLayout(path string) (*PolicyV2, error) {
	layoutBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	layout := &PolicyV2{}
	if err := yaml.Unmarshal(layoutBytes, layout); err != nil {
		return nil, err
	}

	return layout, nil
}

type AttestationIdentifier struct {
	Functionary string
}
