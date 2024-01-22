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

package attestation

import (
	"context"
	"crypto"
	"fmt"
	"os"
	"time"

	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
)

type RunType string

const (
	PreMaterialRunType RunType = "prematerial"
	MaterialRunType    RunType = "material"
	ExecuteRunType     RunType = "execute"
	ProductRunType     RunType = "product"
	PostProductRunType RunType = "postproduct"
)

func (r RunType) String() string {
	return string(r)
}

type ErrInvalidOption struct {
	Option string
	Reason string
}

func (e ErrInvalidOption) Error() string {
	return fmt.Sprintf("invalid value for option %v: %v", e.Option, e.Reason)
}

type AttestationContextOption func(ctx *AttestationContext)

func WithContext(ctx context.Context) AttestationContextOption {
	return func(actx *AttestationContext) {
		actx.ctx = ctx
	}
}

func WithHashes(hashes []crypto.Hash) AttestationContextOption {
	return func(ctx *AttestationContext) {
		if len(hashes) > 0 {
			ctx.hashes = hashes
		}
	}
}

func WithWorkingDir(workingDir string) AttestationContextOption {
	return func(ctx *AttestationContext) {
		if workingDir != "" {
			ctx.workingDir = workingDir
		}
	}
}

type CompletedAttestor struct {
	Attestor  Attestor
	StartTime time.Time
	EndTime   time.Time
	Error     error
}

type AttestationContext struct {
	ctx                context.Context
	attestors          []Attestor
	workingDir         string
	hashes             []crypto.Hash
	completedAttestors []CompletedAttestor
	products           map[string]Product
	materials          map[string]cryptoutil.DigestSet
}

type Product struct {
	MimeType string               `json:"mime_type"`
	Digest   cryptoutil.DigestSet `json:"digest"`
}

func NewContext(attestors []Attestor, opts ...AttestationContextOption) (*AttestationContext, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	ctx := &AttestationContext{
		ctx:        context.Background(),
		attestors:  attestors,
		workingDir: wd,
		hashes:     []crypto.Hash{crypto.SHA256},
		materials:  make(map[string]cryptoutil.DigestSet),
		products:   make(map[string]Product),
	}

	for _, opt := range opts {
		opt(ctx)
	}

	return ctx, nil
}

func (ctx *AttestationContext) RunAttestors() error {
	attestors := make(map[RunType][]Attestor)
	for _, attestor := range ctx.attestors {
		if attestor.RunType() == "" {
			return ErrInvalidOption{
				Option: "RunType",
				Reason: fmt.Sprintf("unknown run type %v", attestor.RunType()),
			}
		}
	}

	for _, atts := range attestors {
		for _, att := range atts {
			log.Infof("Starting %v attestor...", att.Name())
			if err := ctx.runAttestor(att); err != nil {
				log.Errorf("Error running %v attestor: %w", att.Name(), err)
				return err
			}
		}
	}

	return nil
}

func (ctx *AttestationContext) runAttestor(attestor Attestor) error {
	startTime := time.Now()
	// NOTE: Not sure if this is the right place to check for an error running the attestor - might be better to let the caller handle it
	if err := attestor.Attest(ctx); err != nil {
		ctx.completedAttestors = append(ctx.completedAttestors, CompletedAttestor{
			Attestor:  attestor,
			StartTime: startTime,
			EndTime:   time.Now(),
			Error:     err,
		})
		return err
	}

	ctx.completedAttestors = append(ctx.completedAttestors, CompletedAttestor{
		Attestor:  attestor,
		StartTime: startTime,
		EndTime:   time.Now(),
	})

	if materialer, ok := attestor.(Materialer); ok {
		ctx.addMaterials(materialer)
	}

	if producer, ok := attestor.(Producer); ok {
		ctx.addProducts(producer)
	}

	return nil
}

func (ctx *AttestationContext) CompletedAttestors() []CompletedAttestor {
	return ctx.completedAttestors
}

func (ctx *AttestationContext) WorkingDir() string {
	return ctx.workingDir
}

func (ctx *AttestationContext) Hashes() []crypto.Hash {
	return ctx.hashes
}

func (ctx *AttestationContext) Context() context.Context {
	return ctx.ctx
}

func (ctx *AttestationContext) Materials() map[string]cryptoutil.DigestSet {
	return ctx.materials
}

func (ctx *AttestationContext) Products() map[string]Product {
	return ctx.products
}

func (ctx *AttestationContext) addMaterials(materialer Materialer) {
	newMats := materialer.Materials()
	for k, v := range newMats {
		ctx.materials[k] = v
	}
}

func (ctx *AttestationContext) addProducts(producter Producer) {
	newProds := producter.Products()
	for k, v := range newProds {
		ctx.products[k] = v
	}
}
