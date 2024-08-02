package oci

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
	Provenance                 Provenance               `json:"buildx.build.provenance"`
	BuildRef                   string                   `json:"buildx.build.ref"`
	ContainerImageConfigDigest string                   `json:"containerimage.config.digest"`
	ContainerImageDescriptor   ContainerImageDescriptor `json:"containerimage.descriptor"`
	ContainerImageDigest       string                   `json:"containerimage.digest"`
	ImageName                  string                   `json:"image.name"`
}
