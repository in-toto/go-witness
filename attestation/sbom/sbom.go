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

package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"path"

	"github.com/spdx/spdx-sbom-generator/pkg/handler"
	"github.com/spdx/spdx-sbom-generator/pkg/models"
	"github.com/testifysec/go-witness/attestation"
)

const (
	Name    = "sbom"
	Type    = "https://witness.dev/attestations/sbom/v0.1"
	RunType = attestation.PreRunType
)

var (
	_ attestation.Attestor = &Attestor{}
)

type Attestor struct {
	models.Document
}

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

func New() *Attestor {
	return &Attestor{}
}

func (a *Attestor) Type() string {
	return Type
}

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	dir, err := os.MkdirTemp("", "sbom")
	if err != nil {
		return err
	}

	handler, err := handler.NewSPDX(handler.SPDXSettings{
		Version:           "witness",
		Path:              ctx.WorkingDir(),
		License:           false,
		Depth:             "",
		OutputDir:         dir,
		Schema:            "2.2",
		Format:            models.OutputFormatJson,
		GlobalSettingFile: "",
	})

	if err != nil {
		return err
	}

	err = handler.Run()
	if err != nil {
		return err
	}

	err = handler.Complete()
	if err != nil {
		return err
	}

	//get files in dir
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	//get the first file
	if len(files) == 0 {
		return fmt.Errorf("SBOM file not found in temp directory")
	}

	file := files[0]

	//marshal file into Document
	name := file.Name()
	//join path
	f, err := os.Open(path.Join(dir, name))
	if err != nil {
		return err
	}

	err = json.NewDecoder(f).Decode(&a.Document)
	if err != nil {
		return err
	}

	//remove temp dir
	err = os.RemoveAll(dir)
	if err != nil {
		return err
	}

	return nil
}
