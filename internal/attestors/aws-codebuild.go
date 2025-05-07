// Copyright 2025 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package attestors

import (
	"github.com/in-toto/go-witness/attestation"
	aws_codebuild "github.com/in-toto/go-witness/attestation/aws-codebuild"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/invopop/jsonschema"
)

var _ aws_codebuild.AWSCodeBuildAttestor = &TestAWSCodeBuildAttestor{}

type TestAWSCodeBuildAttestor struct {
	awsCodeBuildAtt aws_codebuild.Attestor
}

func NewTestAWSCodeBuildAttestor() *TestAWSCodeBuildAttestor {
	att := aws_codebuild.Attestor{}
	return &TestAWSCodeBuildAttestor{awsCodeBuildAtt: att}
}

func (t *TestAWSCodeBuildAttestor) Name() string {
	return t.awsCodeBuildAtt.Name()
}

func (t *TestAWSCodeBuildAttestor) Type() string {
	return t.awsCodeBuildAtt.Type()
}

func (t *TestAWSCodeBuildAttestor) RunType() attestation.RunType {
	return t.awsCodeBuildAtt.RunType()
}

func (t *TestAWSCodeBuildAttestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&t)
}

func (t *TestAWSCodeBuildAttestor) Attest(ctx *attestation.AttestationContext) error {
	return nil
}

func (t *TestAWSCodeBuildAttestor) Data() *aws_codebuild.Attestor {
	return &t.awsCodeBuildAtt
}

func (t *TestAWSCodeBuildAttestor) Subjects() map[string]cryptoutil.DigestSet {
	return nil
}

func (t *TestAWSCodeBuildAttestor) BackRefs() map[string]cryptoutil.DigestSet {
	return nil
}
