// Copyright 2022 The Witness Contributors
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

package witness

// all of the following imports are here so that each of the package's init functions run appropriately
import (
	// attestors
	_ "github.com/in-toto/go-witness/attestation/aws-codebuild"
	_ "github.com/in-toto/go-witness/attestation/aws-iid"
	_ "github.com/in-toto/go-witness/attestation/commandrun"
	_ "github.com/in-toto/go-witness/attestation/docker"
	_ "github.com/in-toto/go-witness/attestation/environment"
	_ "github.com/in-toto/go-witness/attestation/gcp-iit"
	_ "github.com/in-toto/go-witness/attestation/git"
	_ "github.com/in-toto/go-witness/attestation/github"
	_ "github.com/in-toto/go-witness/attestation/gitlab"
	_ "github.com/in-toto/go-witness/attestation/jenkins"
	_ "github.com/in-toto/go-witness/attestation/jwt"
	_ "github.com/in-toto/go-witness/attestation/k8smanifest"
	_ "github.com/in-toto/go-witness/attestation/link"
	_ "github.com/in-toto/go-witness/attestation/lockfiles"
	_ "github.com/in-toto/go-witness/attestation/material"
	_ "github.com/in-toto/go-witness/attestation/maven"
	_ "github.com/in-toto/go-witness/attestation/oci"
	_ "github.com/in-toto/go-witness/attestation/omnitrail"
	_ "github.com/in-toto/go-witness/attestation/policyverify"
	_ "github.com/in-toto/go-witness/attestation/product"
	_ "github.com/in-toto/go-witness/attestation/sarif"
	_ "github.com/in-toto/go-witness/attestation/sbom"
	_ "github.com/in-toto/go-witness/attestation/secretscan"
	_ "github.com/in-toto/go-witness/attestation/slsa"
	_ "github.com/in-toto/go-witness/attestation/system-packages"
	_ "github.com/in-toto/go-witness/attestation/vex"

	// signer providers
	_ "github.com/in-toto/go-witness/signer/file"
	_ "github.com/in-toto/go-witness/signer/fulcio"
	_ "github.com/in-toto/go-witness/signer/spiffe"
	_ "github.com/in-toto/go-witness/signer/vault"
)
