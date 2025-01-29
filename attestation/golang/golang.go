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

package golang

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "golang"
	Type    = "https://witness.dev/attestations/golang/v0.1"
	RunType = attestation.PostProductRunType
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor = &Attestor{}

	mimeTypes = []string{"text/plain", "application/json"}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type Attestor struct {
	OutputFile          string               `json:"outputFile"`
	PercentageCoverage  float64              `json:"percentageCoverage"`
	Pass                bool                 `json:"pass"`
	Packages            map[string]Package   `json:"package"`
	OutputFileDigestSet cryptoutil.DigestSet `json:"reportDigestSet"`
}

type Package struct {
	Element
	PercentageCoverage float64         `json:"percentageCoverage"`
	Tests              map[string]Test `json:"tests"`
}

type Element struct {
	Name    string   `json:"name"`
	Pass    bool     `json:"pass"`
	Outputs []string `json:"output"`
}

type Test struct {
	Element
}

type GoOutput struct {
	Time    string  `json:"Time"`    // Timestamp of the event (e.g., "2025-01-28T12:00:00.000Z")
	Action  string  `json:"Action"`  // Action type: "run", "output", or "pass" (also "fail" or "skip")
	Package string  `json:"Package"` // Package name (e.g., "example.com/mypackage")
	Test    string  `json:"Test"`    // Test name (only for test-related events)
	Output  string  `json:"Output"`  // Test output (for "output" actions)
	Elapsed float64 `json:"Elapsed"` // Time taken for the test (only for "pass" or "fail" actions)
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
	if err := a.getCandidate(ctx); err != nil {
		log.Debugf("(attestation/golang) error getting candidate: %w", err)
		return err
	}

	return nil
}

func (a *Attestor) getCandidate(ctx *attestation.AttestationContext) error {
	products := ctx.Products()
	if len(products) == 0 {
		return fmt.Errorf("no products to attest")
	}

	for path, product := range products {
		for _, mimeType := range mimeTypes {
			if !strings.Contains(mimeType, product.MimeType) {
				continue
			}
		}

		newDigestSet, err := cryptoutil.CalculateDigestSetFromFile(path, ctx.Hashes())
		if newDigestSet == nil || err != nil {
			return fmt.Errorf("error calculating digest set from file: %s", path)
		}

		if !newDigestSet.Equal(product.Digest) {
			return fmt.Errorf("integrity error: product digest set does not match candidate digest set")
		}

		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("error opening file: %s", path)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)

		a.Packages = map[string]Package{}
		var cancel bool

		totalPass := true
		totalCoverage := 0.0
		for scanner.Scan() {
			line := scanner.Bytes()

			var output GoOutput
			err := json.Unmarshal(line, &output)
			if err != nil {
				log.Debugf("(attestation/golang) error unmarshaling go output file: %w", err)
				// NOTE: we want to move to the next product
				cancel = true
				break
			}

			var ok bool
			var pack Package
			if pack, ok = a.Packages[output.Package]; !ok {
				pack = Package{
					Element: Element{
						Name:    output.Package,
						Outputs: []string{},
					},
					Tests: map[string]Test{},
				}
			}

			if output.Test != "" {
				var test Test
				if test, ok = pack.Tests[output.Test]; !ok {
					test = Test{
						Element: Element{
							Name:    output.Package,
							Outputs: []string{},
						},
					}
				}

				percent := parseJsonBlock(&test.Element, output)
				if percent != nil {
					log.Debugf("(attestation/golang) unexpected percentage %f found in output %s for test %s", *percent, output.Output, output.Test)
				}

				pack.Tests[output.Test] = test
			} else {
				percent := parseJsonBlock(&pack.Element, output)
				if percent != nil {
					pack.PercentageCoverage = *percent
					totalCoverage += *percent
				}

				// NOTE: we only need to check the total package's test for a pass/fail
				if !pack.Pass {
					totalPass = false
				}
			}

			a.Packages[output.Package] = pack
		}

		if cancel {
			continue
		}

		// NOTE: to get the average we need to divide by the number of packages
		totalCoverage = totalCoverage / float64(len(a.Packages))

		a.PercentageCoverage = totalCoverage
		a.Pass = totalPass

		a.OutputFile = path
		a.OutputFileDigestSet = product.Digest

		return nil
	}

	return fmt.Errorf("no golang file found")
}

func parseJsonBlock(elem *Element, output GoOutput) *float64 {
	switch output.Action {
	case "output":
		if output.Output == "" {
			log.Debugf("(attestation/golang) empty output found for element %s", elem.Name)
			return nil
		} else if strings.HasSuffix(output.Output, "% of statements\n") {
			percentage := parsePercentFromOutput(output.Output)
			elem.Outputs = append(elem.Outputs, output.Output)
			return &percentage
		}

		elem.Outputs = append(elem.Outputs, output.Output)
	case "pass":
		elem.Pass = true
	case "fail":
		elem.Pass = false
	default:
		log.Debugf("(attestation/golang) ignoring action %s", output.Action)
		return nil
	}

	return nil
}

func parsePercentFromOutput(output string) float64 {
	start := strings.Index(output, "coverage:")
	if start == -1 {
		log.Debugf("(attestation/golang) failed to get percentage coverage on output %s", output)
		return 0
	}

	substring := output[start+len("coverage: "):]
	parts := strings.Split(substring, " ")
	if len(parts) == 0 {
		log.Debugf("(attestation/golang) failed to get percentage coverage on output %s", output)
		return 0
	}

	percentageStr := strings.TrimSuffix(parts[0], "%")
	percentage, err := strconv.ParseFloat(percentageStr, 64)
	if err != nil {
		log.Debugf("(attestation/golang) error parsing percentage on output %s: %w", output, err)
		return 0
	}

	return percentage
}
