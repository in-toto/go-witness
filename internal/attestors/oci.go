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

package attestors

import (
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/attestation/oci"
	"github.com/in-toto/go-witness/cryptoutil"
)

var (
	_ oci.OCIAttestor = &TestOCIAttestor{}
)

type TestOCIAttestor struct {
	ociAtt oci.Attestor
}

func NewTestOCIAttestor() *TestOCIAttestor {
	att := oci.New()
	return &TestOCIAttestor{ociAtt: *att}
}

func (t *TestOCIAttestor) Name() string {
	return t.ociAtt.Name()
}

func (t *TestOCIAttestor) Type() string {
	return t.ociAtt.Type()
}

func (t *TestOCIAttestor) RunType() attestation.RunType {
	return t.ociAtt.RunType()
}

func (t *TestOCIAttestor) Attest(ctx *attestation.AttestationContext) error {
	return nil
}

func (t *TestOCIAttestor) Data() *oci.Attestor {
	return &t.ociAtt
}

func (t *TestOCIAttestor) Subjects() map[string]cryptoutil.DigestSet {
	return nil
}

func (t *TestOCIAttestor) BackRefs() map[string]cryptoutil.DigestSet {
	return nil
}
