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
	"sync"
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
	VerifyRunType      RunType = "verify"
)

func runTypeOrder() []RunType {
	return []RunType{PreMaterialRunType, MaterialRunType, ExecuteRunType, ProductRunType, PostProductRunType}
}

func verifyTypeOrder() []RunType {
	return []RunType{VerifyRunType}
}

func (r RunType) String() string {
	return string(r)
}

type ErrAttestor struct {
	Name    string
	RunType RunType
	Reason  string
}

func (e ErrAttestor) Error() string {
	return fmt.Sprintf("error returned for attestor %s of run type %s: %s", e.Name, e.RunType, e.Reason)
}

type AttestationContextOption func(ctx *AttestationContext)

func WithContext(ctx context.Context) AttestationContextOption {
	return func(actx *AttestationContext) {
		actx.ctx = ctx
	}
}

func WithHashes(hashes []cryptoutil.DigestValue) AttestationContextOption {
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
	hashes             []cryptoutil.DigestValue
	completedAttestors []CompletedAttestor
	products           map[string]Product
	materials          map[string]cryptoutil.DigestSet
	stepName           string
	mutex              sync.RWMutex
}

type Product struct {
	MimeType string               `json:"mime_type"`
	Digest   cryptoutil.DigestSet `json:"digest"`
}

func NewContext(stepName string, attestors []Attestor, opts ...AttestationContextOption) (*AttestationContext, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	ctx := &AttestationContext{
		ctx:        context.Background(),
		attestors:  attestors,
		workingDir: wd,
		hashes:     []cryptoutil.DigestValue{{Hash: crypto.SHA256}, {Hash: crypto.SHA256, GitOID: true}, {Hash: crypto.SHA1, GitOID: true}},
		materials:  make(map[string]cryptoutil.DigestSet),
		products:   make(map[string]Product),
		stepName:   stepName,
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
			return ErrAttestor{
				Name:    attestor.Name(),
				RunType: attestor.RunType(),
				Reason:  "attestor run type not set",
			}
		}
		attestors[attestor.RunType()] = append(attestors[attestor.RunType()], attestor)
	}

	order := runTypeOrder()
	if attestors[VerifyRunType] != nil && len(attestors) > 1 {
		return fmt.Errorf("attestors of type %s cannot be run in conjunction with other attestor types", VerifyRunType)
	} else if attestors[VerifyRunType] != nil {
		order = verifyTypeOrder()
	}

	for _, k := range order {
		log.Infof("Starting %s attestors stage...", k.String())

		var wg sync.WaitGroup
		ch := make(chan int, len(attestors))

		for _, att := range attestors[k] {
			wg.Add(1)
			go func(att Attestor) {
				defer func() { wg.Done(); <-ch }()
				ctx.runAttestor(att)
			}(att)
		}
		wg.Wait()
		log.Infof("Completed %s attestors stage...", k.String())
	}

	return nil
}

func (ctx *AttestationContext) runAttestor(attestor Attestor) {
	log.Infof("Starting %v attestor...", attestor.Name())

	startTime := time.Now()
	if err := attestor.Attest(ctx); err != nil {
		ctx.mutex.Lock()
		ctx.completedAttestors = append(ctx.completedAttestors, CompletedAttestor{
			Attestor:  attestor,
			StartTime: startTime,
			EndTime:   time.Now(),
			Error:     err,
		})
		ctx.mutex.Unlock()
	}

	ctx.mutex.Lock()
	ctx.completedAttestors = append(ctx.completedAttestors, CompletedAttestor{
		Attestor:  attestor,
		StartTime: startTime,
		EndTime:   time.Now(),
	})
	ctx.mutex.Unlock()

	if materialer, ok := attestor.(Materialer); ok {
		ctx.mutex.Lock()
		ctx.addMaterials(materialer)
		ctx.mutex.Unlock()
	}

	if producer, ok := attestor.(Producer); ok {
		ctx.mutex.Lock()
		ctx.addProducts(producer)
		ctx.mutex.Unlock()
	}

	log.Infof("Finished %v attestor... (%vs)", attestor.Name(), time.Since(startTime).Seconds())
}

func (ctx *AttestationContext) CompletedAttestors() []CompletedAttestor {
	ctx.mutex.RLock()
	out := make([]CompletedAttestor, len(ctx.completedAttestors))
	copy(out, ctx.completedAttestors)
	ctx.mutex.RUnlock()
	return out
}

func (ctx *AttestationContext) WorkingDir() string {
	return ctx.workingDir
}

func (ctx *AttestationContext) Hashes() []cryptoutil.DigestValue {
	ctx.mutex.RLock()
	hashes := make([]cryptoutil.DigestValue, len(ctx.hashes))
	copy(hashes, ctx.hashes)
	ctx.mutex.RUnlock()
	return hashes
}

func (ctx *AttestationContext) Context() context.Context {
	return ctx.ctx
}

func (ctx *AttestationContext) Materials() map[string]cryptoutil.DigestSet {
	ctx.mutex.RLock()
	out := make(map[string]cryptoutil.DigestSet)
	for k, v := range ctx.materials {
		out[k] = v
	}
	ctx.mutex.RUnlock()
	return out
}

func (ctx *AttestationContext) Products() map[string]Product {
	ctx.mutex.RLock()
	out := make(map[string]Product)
	for k, v := range ctx.products {
		out[k] = v
	}
	ctx.mutex.RUnlock()
	return out
}

func (ctx *AttestationContext) StepName() string {
	return ctx.stepName
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
