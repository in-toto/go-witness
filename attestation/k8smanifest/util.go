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

package k8smanifest

import (
	"github.com/google/go-containerregistry/pkg/name"
	remote "github.com/google/go-containerregistry/pkg/v1/remote"
)

var (
	remoteGet = remote.Get
)

// Taken from github.com/sigstore/cosign/v2/pkg/oci/remote
func resolveDigest(ref name.Reference) (name.Digest, error) {
	desc, err := remoteGet(ref)
	if err != nil {
		return name.Digest{}, err
	}
	return ref.Context().Digest(desc.Digest.String()), nil
}

func DigestForRef(reference string) (string, error) {
	ref, err := name.ParseReference(reference)
	if err != nil {
		return "", err
	}

	nref, err := resolveDigest(ref)
	if err != nil {
		return "", err
	}

	return nref.DigestStr(), nil
}
