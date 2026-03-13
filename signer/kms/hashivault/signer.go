// Copyright 2024 The Witness Contributors
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

package hashivault

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"strconv"

	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/signer/kms"
)

var (
	supportedHashesToString = map[crypto.Hash]string{
		crypto.SHA224: "sha2-224",
		crypto.SHA256: "sha2-256",
		crypto.SHA384: "sha2-384",
		crypto.SHA512: "sha2-512",
	}
)

type SignerVerifier struct {
	reference string
	hashFunc  crypto.Hash
	client    *client
}

func LoadSignerVerifier(ctx context.Context, ksp *kms.KMSSignerProvider) (*SignerVerifier, error) {
	potentialOpts := ksp.Options[providerName]
	clientOpts, ok := potentialOpts.(*clientOptions)
	if !ok {
		return nil, fmt.Errorf("unexpected client options type: %T", potentialOpts)
	}

	keyPath, err := parseReference(ksp.Reference)
	if err != nil {
		return nil, fmt.Errorf("could not parse vault ref: %w", err)
	}
	clientOpts.keyPath = keyPath

	_, ok = supportedHashesToString[ksp.HashFunc]
	if !ok {
		return nil, fmt.Errorf("vault does not support provided hash function %v", ksp.HashFunc.String())
	}

	if len(ksp.KeyVersion) > 0 {
		keyVer, err := strconv.ParseInt(ksp.KeyVersion, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid vault key version %v: %w", ksp.KeyVersion, err)
		}

		clientOpts.keyVersion = int32(keyVer)
	}

	client, err := newClient(ctx, clientOpts)
	if err != nil {
		return nil, fmt.Errorf("could not create vault client: %w", err)
	}
	sv := &SignerVerifier{
		reference: ksp.Reference,
		client:    client,
		hashFunc:  ksp.HashFunc,
	}

	return sv, nil
}

func (sv *SignerVerifier) KeyID() (string, error) {
	return sv.reference, nil
}

func (sv *SignerVerifier) Sign(r io.Reader) ([]byte, error) {
	ctx := context.TODO()
	digest, err := cryptoutil.Digest(r, sv.hashFunc)
	if err != nil {
		return nil, fmt.Errorf("could not calculate digest: %w", err)
	}

	return sv.client.sign(ctx, digest, sv.hashFunc)
}

func (sv *SignerVerifier) Verifier() (cryptoutil.Verifier, error) {
	return sv, nil
}

func (sv *SignerVerifier) Bytes() ([]byte, error) {
	return sv.client.getPublicKeyBytes(context.TODO())
}

func (sv *SignerVerifier) Verify(r io.Reader, sig []byte) error {
	return sv.client.verify(context.TODO(), r, sig, sv.hashFunc)
}

func parseReference(resourceID string) (string, error) {
	keyPath := ""
	i := referenceRegex.SubexpIndex("path")
	v := referenceRegex.FindStringSubmatch(resourceID)
	if len(v) < i+1 {
		return keyPath, fmt.Errorf("invalid vault format %q", resourceID)
	}

	keyPath = v[i]
	return keyPath, nil
}
