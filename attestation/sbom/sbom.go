package sbom

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/log"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "sbom"
	Type    = "https://witness.dev/attestations/sbom/v0.1"
	RunType = attestation.PostProductRunType

	SPDXPredicateType      = "https://spdx.dev/Document"
	SPDXMimeType           = "application/spdx+json"
	CycloneDxPredicateType = "https://cyclonedx.org/bom"
	CycloneDxMimeType      = "application/vnd.cyclonedx+json"
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor = &SBOMAttestor{}
	_ attestation.Exporter = &SBOMAttestor{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return NewSBOMAttestor()
	})
}

type Option func(*SBOMAttestor)

func WithExport(export bool) Option {
	return func(a *SBOMAttestor) {
		a.export = export
	}
}

type SBOMAttestor struct {
	SBOMDocument  interface{}
	predicateType string
	export        bool
}

func NewSBOMAttestor() *SBOMAttestor {
	return &SBOMAttestor{
		predicateType: Type,
	}
}

func (a *SBOMAttestor) Name() string {
	return Name
}

func (a *SBOMAttestor) Type() string {
	return a.predicateType
}

func (a *SBOMAttestor) RunType() attestation.RunType {
	return RunType
}

func (a *SBOMAttestor) Export() bool {
	return a.export
}

func (a *SBOMAttestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(a.SBOMDocument)
}

func (a *SBOMAttestor) Attest(ctx *attestation.AttestationContext) error {
	if err := a.getCandidate(ctx); err != nil {
		log.Debugf("(attestation/sbom) error getting candidate: %w", err)
		return err
	}

	return nil
}

func (a *SBOMAttestor) MarshalJSON() ([]byte, error) {
	return json.Marshal(&a.SBOMDocument)
}

func (a *SBOMAttestor) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &a.SBOMDocument); err != nil {
		return err
	}

	return nil
}

func (a *SBOMAttestor) getCandidate(ctx *attestation.AttestationContext) error {
	products := ctx.Products()

	if len(products) == 0 {
		return fmt.Errorf("no products to attest")
	}

	for path, product := range products {
		if product.MimeType == SPDXMimeType {
			a.predicateType = SPDXPredicateType
		} else if product.MimeType == CycloneDxMimeType {
			a.predicateType = CycloneDxPredicateType
		} else {
			continue
		}

		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("error opening file: %s", path)
		}

		sbomBytes, err := io.ReadAll(f)
		if err != nil {
			return fmt.Errorf("error reading file: %s", path)
		}

		var sbomDocument interface{}
		if err := json.Unmarshal(sbomBytes, &sbomDocument); err != nil {
			log.Debugf("(attestation/sbom) error unmarshaling SBOM: %w", err)
			continue
		}

		a.SBOMDocument = sbomDocument

		return nil
	}

	return fmt.Errorf("no SBOM file found")
}
