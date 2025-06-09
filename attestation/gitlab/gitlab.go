// Copyright 2021 The Witness Contributors
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

package gitlab

import (
	"crypto"
	"fmt"
	"os"
	"strings"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/jwt"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "gitlab"
	Type    = "https://witness.dev/attestations/gitlab/v0.1"
	RunType = attestation.PreMaterialRunType
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor   = &Attestor{}
	_ attestation.Subjecter  = &Attestor{}
	_ attestation.BackReffer = &Attestor{}
	_ GitLabAttestor         = &Attestor{}
)

type GitLabAttestor interface {
	// Attestor
	Name() string
	Type() string
	RunType() attestation.RunType
	Attest(ctx *attestation.AttestationContext) error
	Data() *Attestor

	// Subjecter
	Subjects() map[string]cryptoutil.DigestSet

	// Backreffer
	BackRefs() map[string]cryptoutil.DigestSet
}

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type ErrNotGitlab struct{}

func (e ErrNotGitlab) Error() string {
	return "not in a gitlab ci job"
}

type Option func(a *Attestor)

type Attestor struct {
	JWT          *jwt.Attestor `json:"jwt,omitempty" jsonschema:"title=JWT,description=The underlying JWT attestation containing the GitLab CI job token"`
	CIConfigPath string        `json:"ciconfigpath" jsonschema:"title=CI Config Path,description=Path to the GitLab CI configuration file"`
	JobID        string        `json:"jobid" jsonschema:"title=Job ID,description=GitLab CI job ID,example=1234567890"`
	JobImage     string        `json:"jobimage" jsonschema:"title=Job Image,description=Docker image used for the job"`
	JobName      string        `json:"jobname" jsonschema:"title=Job Name,description=Name of the GitLab CI job"`
	JobStage     string        `json:"jobstage" jsonschema:"title=Job Stage,description=Stage of the GitLab CI job,example=build"`
	JobUrl       string        `json:"joburl" jsonschema:"title=Job URL,description=URL to the GitLab CI job"`
	PipelineID   string        `json:"pipelineid" jsonschema:"title=Pipeline ID,description=GitLab CI pipeline ID"`
	PipelineUrl  string        `json:"pipelineurl" jsonschema:"title=Pipeline URL,description=URL to the GitLab CI pipeline"`
	ProjectID    string        `json:"projectid" jsonschema:"title=Project ID,description=GitLab project ID"`
	ProjectUrl   string        `json:"projecturl" jsonschema:"title=Project URL,description=URL to the GitLab project"`
	RunnerID     string        `json:"runnerid" jsonschema:"title=Runner ID,description=ID of the GitLab runner"`
	CIHost       string        `json:"cihost" jsonschema:"title=CI Host,description=GitLab server hostname"`
	CIServerUrl  string        `json:"ciserverurl" jsonschema:"title=CI Server URL,description=GitLab server URL,example=https://gitlab.com"`
	token        string
	tokenEnvVar  string
}

func WithToken(token string) Option {
	return func(a *Attestor) {
		a.token = token
	}
}

func WithTokenEnvVar(envVar string) Option {
	return func(a *Attestor) {
		a.tokenEnvVar = envVar
	}
}

func New(opts ...Option) *Attestor {
	a := &Attestor{}

	for _, opt := range opts {
		opt(a)
	}

	return a
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
	// NOTE: This isn't ideal. For some reason the reflect function is return an empty schema when passing in `p`
	// TODO: Fix this later
	schema := jsonschema.Reflect(&a)
	schema.Definitions["Attestor"].Properties.Set("jwt", jsonschema.Reflect(&a.JWT))
	return schema
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	if os.Getenv("GITLAB_CI") != "true" {
		return ErrNotGitlab{}
	}

	a.CIServerUrl = os.Getenv("CI_SERVER_URL")
	jwksUrl := fmt.Sprintf("%s/oauth/discovery/keys", a.CIServerUrl)

	var jwtString string
	if a.token != "" {
		jwtString = a.token
	} else if a.tokenEnvVar != "" {
		jwtString = os.Getenv(a.tokenEnvVar)
	} else {
		// Only works in GitLab < 17.0
		jwtString = os.Getenv("CI_JOB_JWT")
	}

	if jwtString != "" {
		a.JWT = jwt.New(jwt.WithToken(jwtString), jwt.WithJWKSUrl(jwksUrl))
		if err := a.JWT.Attest(ctx); err != nil {
			return err
		}
	} else {
		log.Warn("(attestation/gitlab) no jwt token found in environment")
	}

	a.CIConfigPath = os.Getenv("CI_CONFIG_PATH")
	a.JobID = os.Getenv("CI_JOB_ID")
	a.JobImage = os.Getenv("CI_JOB_IMAGE")
	a.JobName = os.Getenv("CI_JOB_NAME")
	a.JobStage = os.Getenv("CI_JOB_STAGE")
	a.JobUrl = os.Getenv("CI_JOB_URL")
	a.PipelineID = os.Getenv("CI_PIPELINE_ID")
	a.PipelineUrl = os.Getenv("CI_PIPELINE_URL")
	a.ProjectID = os.Getenv("CI_PROJECT_ID")
	a.ProjectUrl = os.Getenv("CI_PROJECT_URL")
	a.RunnerID = os.Getenv("CI_RUNNER_ID")
	a.CIHost = os.Getenv("CI_SERVER_HOST")

	return nil
}

func (a *Attestor) Data() *Attestor {
	return a
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	subjects := make(map[string]cryptoutil.DigestSet)
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(a.PipelineUrl), hashes); err == nil {
		subjects[fmt.Sprintf("pipelineurl:%v", a.PipelineUrl)] = ds
	} else {
		log.Debugf("(attestation/gitlab) failed to record gitlab pipelineurl subject: %w", err)
	}

	if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(a.JobUrl), hashes); err == nil {
		subjects[fmt.Sprintf("joburl:%v", a.JobUrl)] = ds
	} else {
		log.Debugf("(attestation/gitlab) failed to record gitlab joburl subject: %w", err)
	}

	if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(a.ProjectUrl), hashes); err == nil {
		subjects[fmt.Sprintf("projecturl:%v", a.ProjectUrl)] = ds
	} else {
		log.Debugf("(attestation/gitlab) failed to record gitlab projecturl subject: %w", err)
	}

	return subjects
}

func (a *Attestor) Documentation() attestation.Documentation {
	return attestation.Documentation{
		Summary: "Captures GitLab CI/CD pipeline execution context",
		Usage: []string{
			"Automatically captures GitLab CI context when GITLAB_CI=true",
			"Supports JWT verification using CI_JOB_JWT token (GitLab < 17.0)",
			"Can be configured with custom tokens using WithToken or WithTokenEnvVar options",
		},
		Example: "witness run -s test -k key.pem -a gitlab -- gradle test",
	}
}

func (a *Attestor) BackRefs() map[string]cryptoutil.DigestSet {
	backRefs := make(map[string]cryptoutil.DigestSet)
	for subj, ds := range a.Subjects() {
		if strings.HasPrefix(subj, "pipelineurl:") {
			backRefs[subj] = ds
			break
		}
	}

	return backRefs
}
