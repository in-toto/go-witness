package sbom

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
)

const (
	Name    = "sbom"
	Type    = "https://witness.dev/attestations/sbom/v0.1"
	RunType = attestation.PostProductRunType

	spdxMimeType      = "application/spdx+json"
	cycloneDxMimeType = "application/vnd.cyclonedx+json"
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return NewSBOMAttestor()
	})
}

type SBOMAttestor struct {
	SBOMDocument  interface{}          `json:"sbomDocument"`
	SBOMFile      string               `json:"sbomFileName"`
	SBOMDigestSet cryptoutil.DigestSet `json:"sbomDigestSet"`
}

func NewSBOMAttestor() *SBOMAttestor {
	return &SBOMAttestor{}
}

func (a *SBOMAttestor) Name() string {
	return Name
}

func (a *SBOMAttestor) Type() string {
	return Type
}

func (a *SBOMAttestor) RunType() attestation.RunType {
	return RunType
}

func (a *SBOMAttestor) Attest(ctx *attestation.AttestationContext) error {
	if err := a.getCandidate(ctx); err != nil {
		log.Debugf("(attestation/sbom) error getting candidate: %w", err)
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
		if product.MimeType != spdxMimeType && product.MimeType != cycloneDxMimeType {
			continue
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

		sbomBytes, err := io.ReadAll(f)
		if err != nil {
			return fmt.Errorf("error reading file: %s", path)
		}

		var sbomDocument interface{}
		if err := json.Unmarshal(sbomBytes, &sbomDocument); err != nil {
			log.Debugf("(attestation/sbom) error unmarshaling SBOM: %w", err)
			continue
		}

		a.SBOMFile = path
		a.SBOMDigestSet = product.Digest
		a.SBOMDocument = sbomDocument

		return nil
	}
	return fmt.Errorf("no SBOM file found")
}
