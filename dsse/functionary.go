package dsse

import (
	"encoding/base64"

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

type Base64Key string

type KeyVal struct {
	Public Base64Key `yaml:"public"`
}

func (f *Base64Key) UnmarshalYAML(value *yaml.Node) error {
	var encodedKey string
	if err := value.Decode(&encodedKey); err != nil {
		return err
	}

	decodedKey, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return err
	}

	*f = Base64Key(decodedKey)
	return nil
}
