// Copyright 2025 The Witness Contributors
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

package aws_codebuild

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "aws-codebuild"
	Type    = "https://witness.dev/attestations/aws-codebuild/v0.1"
	RunType = attestation.PreMaterialRunType

	// Environment variables available in AWS CodeBuild
	envCodeBuildBuildID            = "CODEBUILD_BUILD_ID"
	envCodeBuildBuildARN           = "CODEBUILD_BUILD_ARN"
	envCodeBuildBuildNumber        = "CODEBUILD_BUILD_NUMBER"
	envCodeBuildInitiator          = "CODEBUILD_INITIATOR"
	envCodeBuildProjectName        = "CODEBUILD_PROJECT_NAME"
	envCodeBuildResolvedSrcVer     = "CODEBUILD_RESOLVED_SOURCE_VERSION"
	envCodeBuildSourceRepo         = "CODEBUILD_SOURCE_REPO_URL"
	envCodeBuildBatchBuildID       = "CODEBUILD_BATCH_BUILD_IDENTIFIER"
	envCodeBuildWebhookEvent       = "CODEBUILD_WEBHOOK_EVENT"
	envCodeBuildWebhookHeadRef     = "CODEBUILD_WEBHOOK_HEAD_REF"
	envCodeBuildWebhookActorAcctID = "CODEBUILD_WEBHOOK_ACTOR_ACCOUNT_ID"
	envAWSRegion                   = "AWS_REGION"
)

// Ensure Attestor implements the required interfaces at compile time
var (
	_ attestation.Attestor   = &Attestor{}
	_ attestation.Subjecter  = &Attestor{}
	_ attestation.BackReffer = &Attestor{}
	_ AWSCodeBuildAttestor   = &Attestor{}
)

type AWSCodeBuildAttestor interface {
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

// BuildInfo represents AWS CodeBuild metadata
type BuildInfo struct {
	BuildID        string       `json:"build_id"`
	BuildARN       string       `json:"build_arn,omitempty"`
	BuildNumber    string       `json:"build_number,omitempty"`
	ProjectName    string       `json:"project_name,omitempty"`
	Initiator      string       `json:"initiator,omitempty"`
	SourceVersion  string       `json:"source_version,omitempty"`
	SourceRepo     string       `json:"source_repo,omitempty"`
	BatchBuildID   string       `json:"batch_build_id,omitempty"`
	WebhookEvent   string       `json:"webhook_event,omitempty"`
	WebhookHeadRef string       `json:"webhook_head_ref,omitempty"`
	WebhookActorID string       `json:"webhook_actor_id,omitempty"`
	Region         string       `json:"region,omitempty"`
	BuildDetails   *types.Build `json:"build_details,omitempty"`
}

type Attestor struct {
	hashes          []cryptoutil.DigestValue
	awsConfig       aws.Config
	BuildInfo       BuildInfo `json:"build_info"`
	RawBuildDetails string    `json:"raw_build_details,omitempty"`
}

func New() *Attestor {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return &Attestor{
			BuildInfo: BuildInfo{},
		}
	}

	// If AWS_REGION is available, use it explicitly
	if region := os.Getenv(envAWSRegion); region != "" {
		cfg.Region = region
	}

	return &Attestor{
		awsConfig: cfg,
		BuildInfo: BuildInfo{},
	}
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
	return jsonschema.Reflect(a)
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	a.hashes = ctx.Hashes()

	// First check if we are running in CodeBuild
	buildID := os.Getenv(envCodeBuildBuildID)
	if buildID == "" {
		return fmt.Errorf("not running in AWS CodeBuild environment, CODEBUILD_BUILD_ID not found")
	}

	// Initialize basic metadata from environment variables
	a.BuildInfo.BuildID = buildID
	a.BuildInfo.BuildARN = os.Getenv(envCodeBuildBuildARN)
	a.BuildInfo.BuildNumber = os.Getenv(envCodeBuildBuildNumber)
	a.BuildInfo.ProjectName = os.Getenv(envCodeBuildProjectName)
	a.BuildInfo.Initiator = os.Getenv(envCodeBuildInitiator)
	a.BuildInfo.SourceVersion = os.Getenv(envCodeBuildResolvedSrcVer)
	a.BuildInfo.SourceRepo = os.Getenv(envCodeBuildSourceRepo)
	a.BuildInfo.BatchBuildID = os.Getenv(envCodeBuildBatchBuildID)
	a.BuildInfo.WebhookEvent = os.Getenv(envCodeBuildWebhookEvent)
	a.BuildInfo.WebhookHeadRef = os.Getenv(envCodeBuildWebhookHeadRef)
	a.BuildInfo.WebhookActorID = os.Getenv(envCodeBuildWebhookActorAcctID)
	a.BuildInfo.Region = os.Getenv(envAWSRegion)

	// Try to get more details from the CodeBuild API
	err := a.getBuildDetails()
	if err != nil {
		log.Warnf("Unable to get CodeBuild build details: %v", err)
		// Continue with environment-based metadata only
	}

	return nil
}

func (a *Attestor) getBuildDetails() error {
	ctx := context.Background()

	// Extract the build ID without the project name prefix
	// e.g., project-name:build-id -> build-id
	buildIDParts := strings.Split(a.BuildInfo.BuildID, ":")
	if len(buildIDParts) != 2 {
		return fmt.Errorf("invalid CODEBUILD_BUILD_ID format: %s", a.BuildInfo.BuildID)
	}
	buildID := buildIDParts[1]

	svc := codebuild.NewFromConfig(a.awsConfig)
	input := &codebuild.BatchGetBuildsInput{
		Ids: []string{buildID},
	}

	result, err := svc.BatchGetBuilds(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to get build details: %w", err)
	}

	if len(result.Builds) == 0 {
		return fmt.Errorf("no build found with ID: %s", buildID)
	}

	build := result.Builds[0]
	a.BuildInfo.BuildDetails = &build

	// Store raw build details for verification
	rawDetails, err := json.Marshal(build)
	if err != nil {
		return fmt.Errorf("failed to marshal build details: %w", err)
	}

	a.RawBuildDetails = string(rawDetails)
	return nil
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	subjects := make(map[string]cryptoutil.DigestSet)

	// Add build ID as subject
	if a.BuildInfo.BuildID != "" {
		if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(a.BuildInfo.BuildID), hashes); err == nil {
			subjects[fmt.Sprintf("codebuild-build-id:%s", a.BuildInfo.BuildID)] = ds
		} else {
			log.Debugf("(attestation/aws-codebuild) failed to record build ID subject: %v", err)
		}
	}

	// Add project name as subject
	if a.BuildInfo.ProjectName != "" {
		if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(a.BuildInfo.ProjectName), hashes); err == nil {
			subjects[fmt.Sprintf("codebuild-project:%s", a.BuildInfo.ProjectName)] = ds
		} else {
			log.Debugf("(attestation/aws-codebuild) failed to record project name subject: %v", err)
		}
	}

	// Add source version (git commit) as subject
	if a.BuildInfo.SourceVersion != "" {
		if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(a.BuildInfo.SourceVersion), hashes); err == nil {
			subjects[fmt.Sprintf("codebuild-source-version:%s", a.BuildInfo.SourceVersion)] = ds
		} else {
			log.Debugf("(attestation/aws-codebuild) failed to record source version subject: %v", err)
		}
	}

	return subjects
}

func (a *Attestor) BackRefs() map[string]cryptoutil.DigestSet {
	// Same as Subjects() for now, but we could be more selective in the future
	return a.Subjects()
}

func (a *Attestor) Data() *Attestor {
	return a
}
