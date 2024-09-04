// Copyright 2024 The Witness Contributors
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

package jenkins

import (
	"crypto"
	"fmt"
	"os"
	"strings"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "jenkins"
	Type    = "https://witness.dev/attestations/jenkins/v0.1"
	RunType = attestation.PreMaterialRunType
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor   = &Attestor{}
	_ attestation.Subjecter  = &Attestor{}
	_ attestation.BackReffer = &Attestor{}
	_ JenkinsAttestor        = &Attestor{}
)

type JenkinsAttestor interface {
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

type ErrNotJenkins struct{}

func (e ErrNotJenkins) Error() string {
	return "not in a jenkins ci job"
}

type Attestor struct {
	BuildID        string `json:"buildid"`
	BuildNumber    string `json:"buildnumber"`
	BuildTag       string `json:"buildtag"`
	PipelineUrl    string `json:"pipelineurl"`
	ExecutorNumber string `json:"executornumber"`
	JavaHome       string `json:"javahome"`
	JenkinsUrl     string `json:"jenkinsurl"`
	JobName        string `json:"jobname"`
	NodeName       string `json:"nodename"`
	Workspace      string `json:"workspace"`
}

func New() *Attestor {
	return &Attestor{}
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
	return jsonschema.Reflect(&a)
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	if _, ok := os.LookupEnv("JENKINS_URL"); !ok {
		return ErrNotJenkins{}
	}

	a.BuildID = os.Getenv("BUILD_ID")
	a.BuildNumber = os.Getenv("BUILD_NUMBER")
	a.BuildTag = os.Getenv("BUILD_TAG")
	a.PipelineUrl = os.Getenv("BUILD_URL")
	a.ExecutorNumber = os.Getenv("EXECUTOR_NUMBER")
	a.JavaHome = os.Getenv("JAVA_HOME")
	a.JenkinsUrl = os.Getenv("JENKINS_URL")
	a.JobName = os.Getenv("JOB_NAME")
	a.NodeName = os.Getenv("NODE_NAME")
	a.Workspace = os.Getenv("WORKSPACE")

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
		log.Debugf("(attestation/jenkins) failed to record jenkins pipelineurl subject: %w", err)
	}

	if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(a.JenkinsUrl), hashes); err == nil {
		subjects[fmt.Sprintf("jenkinsurl:%v", a.JenkinsUrl)] = ds
	} else {
		log.Debugf("(attestation/jenkins) failed to record jenkins jenkinsurl subject: %w", err)
	}

	return subjects
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
