package docker

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

type Digest struct {
	Sha256 string `json:"sha256"`
}

type Material struct {
	URI    string `json:"uri"`
	Digest Digest `json:"digest"`
}

type ConfigSource struct {
	EntryPoint string `json:"entryPoint"`
}

type Args struct {
	Cmdline string `json:"cmdline"`
	Source  string `json:"source"`
}

type Local struct {
	Name string `json:"name"`
}

type Parameters struct {
	Frontend string  `json:"frontend"`
	Args     Args    `json:"args"`
	Locals   []Local `json:"locals"`
}

type Environment struct {
	Platform string `json:"platform"`
}

type Invocation struct {
	ConfigSource ConfigSource `json:"configSource"`
	Parameters   Parameters   `json:"parameters"`
	Environment  Environment  `json:"environment"`
}

type Provenance struct {
	BuildType  string     `json:"buildType"`
	Materials  []Material `json:"materials"`
	Invocation Invocation `json:"invocation"`
}

type Platform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

type ContainerImageDescriptor struct {
	MediaType string   `json:"mediaType"`
	Digest    string   `json:"digest"`
	Size      int      `json:"size"`
	Platform  Platform `json:"platform"`
}

type BuildInfo struct {
	Provenance                 map[string]Provenance
	BuildRef                   string                   `json:"buildx.build.ref"`
	ContainerImageConfigDigest string                   `json:"containerimage.config.digest"`
	ContainerImageDescriptor   ContainerImageDescriptor `json:"containerimage.descriptor"`
	ContainerImageDigest       string                   `json:"containerimage.digest"`
	ImageName                  string                   `json:"image.name"`
}

func (b *BuildInfo) UnmarshalJSON(data []byte) error {
	type Alias BuildInfo
	aux := &Alias{}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	*b = BuildInfo(*aux)

	// Provenance looks a bit different so we handle it separately
	b.Provenance = make(map[string]Provenance)

	for key, value := range raw {
		if key == "buildx.build.ref" {
			err := json.Unmarshal(value, &b.BuildRef)
			if err != nil {
				return err
			}
		} else if strings.Contains(key, "buildx.build.provenance") {
			var provenance Provenance
			if err := json.Unmarshal(value, &provenance); err == nil {
				var arch string
				var found bool

				if key == "buildx.build.provenance" {
					for _, mat := range provenance.Materials {
						if parts := strings.Split(mat.URI, "?platform="); len(parts) == 2 {
							arch, err = url.QueryUnescape(parts[1])
							if err != nil {
								continue
							}
						}
					}
				} else {
					arch, found = strings.CutPrefix(key, "buildx.build.provenance/")
					if !found {
						return fmt.Errorf("unexpected provenance prefix on key: %s", key)
					}
				}

				b.Provenance[arch] = provenance
			}
		}
	}

	return nil
}
