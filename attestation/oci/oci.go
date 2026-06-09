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

package oci

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"github.com/invopop/jsonschema"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	Name    = "oci"
	Type    = "https://witness.dev/attestations/oci/v0.1"
	RunType = attestation.PostProductRunType

	mimeTypes = "application/x-tar"
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
	_ OCIAttestor           = &Attestor{}
)

type OCIAttestor interface {
	// Attestor
	Name() string
	Type() string
	RunType() attestation.RunType
	Attest(ctx *attestation.AttestationContext) error

	// Subjector
	Subjects() map[string]cryptoutil.DigestSet
}

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type Attestor struct {
	TarDigest      cryptoutil.DigestSet   `json:"tardigest"`
	Manifest       []Manifest             `json:"manifest"`
	ImageTags      []string               `json:"imagetags"`
	LayerDiffIDs   []cryptoutil.DigestSet `json:"diffids"`
	ImageID        cryptoutil.DigestSet   `json:"imageid"`
	ManifestRaw    []byte                 `json:"manifestraw"`
	ManifestDigest cryptoutil.DigestSet   `json:"manifestdigest"`
	tarFilePath    string                 `json:"-"`
}

type Manifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

func (m *Manifest) getImageID(ctx *attestation.AttestationContext, tarFilePath string) (cryptoutil.DigestSet, error) {
	tarFile, err := os.Open(tarFilePath)
	if err != nil {
		return nil, err
	}
	defer tarFile.Close()

	tarReader := tar.NewReader(tarFile)
	for {
		h, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.FileInfo().IsDir() {
			continue
		}

		if h.Name == m.Config {

			b := make([]byte, h.Size)
			_, err := tarReader.Read(b)
			if err != nil && err != io.EOF {
				return nil, err
			}

			imageID, err := cryptoutil.CalculateDigestSetFromBytes(b, ctx.Hashes())
			if err != nil {
				log.Debugf("(attestation/oci) error calculating image id: %w", err)
				return nil, err
			}

			return imageID, nil
		}
	}
	return nil, fmt.Errorf("could not find config in tar file")
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
		log.Debugf("(attestation/oci) error getting candidate: %w", err)
		return err
	}

	if err := a.parseManifest(ctx); err != nil {
		log.Debugf("(attestation/oci) error parsing manifest: %w", err)
		return err
	}

	imageID, err := a.Manifest[0].getImageID(ctx, a.tarFilePath)
	if err != nil {
		log.Debugf("(attestation/oci) error getting image id: %w", err)
		return err
	}

	layerDiffIDs, err := a.Manifest[0].getLayerDIFFIDs(ctx, a.tarFilePath)
	if err != nil {
		return err
	}

	a.ImageID = imageID
	a.LayerDiffIDs = layerDiffIDs
	a.ImageTags = a.Manifest[0].RepoTags

	return nil
}

func (a *Attestor) getCandidate(ctx *attestation.AttestationContext) error {
	products := ctx.Products()

	if len(products) == 0 {
		return fmt.Errorf("no products to attest")
	}

	for path, product := range products {
		if !strings.Contains(mimeTypes, product.MimeType) {
			continue
		}

		newDigestSet, err := cryptoutil.CalculateDigestSetFromFile(path, ctx.Hashes())
		if newDigestSet == nil || err != nil {
			return fmt.Errorf("error calculating digest set from file: %s", path)
		}

		if !newDigestSet.Equal(product.Digest) {
			return fmt.Errorf("integrity error: product digest set does not match candidate digest set")
		}

		a.TarDigest = product.Digest

		a.tarFilePath = path
		return nil
	}
	return fmt.Errorf("no tar file found")
}

func (a *Attestor) parseManifest(ctx *attestation.AttestationContext) error {
	f, err := os.Open(a.tarFilePath)
	if err != nil {
		err = fmt.Errorf("error opening tar file: %w", err)
		return err
	}
	defer f.Close()

	// Cache the entry points and content-addressed blobs needed by both the
	// OCI image-layout and legacy Docker archive parsers.
	tarReader := tar.NewReader(f)
	files := make(map[string][]byte)
	for {
		h, err := tarReader.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			return fmt.Errorf("read OCI archive %q: %w", a.tarFilePath, err)
		}

		if h.FileInfo().IsDir() {
			continue
		}

		name := strings.TrimPrefix(path.Clean(h.Name), "./")
		if name != "manifest.json" && name != "index.json" && !strings.HasPrefix(name, "blobs/") {
			continue
		}

		b, err := io.ReadAll(tarReader)
		if err != nil {
			return fmt.Errorf("read OCI archive entry %q: %w", name, err)
		}
		files[name] = b
	}

	manifestRaw, ok := files["manifest.json"]

	// Prefer the OCI image-layout entry point when a hybrid archive contains
	// both index.json and Docker's compatibility manifest.json.
	if indexRaw, ok := files["index.json"]; ok {
		if manifestRaw != nil {
			a.logDockerManifestAttestation(ctx, manifestRaw)
		}
		return a.parseOCIManifest(ctx, indexRaw, files)
	}

	if !ok {
		return fmt.Errorf("archive %q contains neither OCI index.json nor Docker manifest.json", a.tarFilePath)
	}

	log.Debug("(attestation/oci) index.json not found; parsing legacy Docker manifest.json")
	return a.parseDockerManifest(ctx, manifestRaw)
}

func (a *Attestor) logDockerManifestAttestation(ctx *attestation.AttestationContext, manifestRaw []byte) {
	dockerAttestor := New()
	dockerAttestor.TarDigest = a.TarDigest
	dockerAttestor.tarFilePath = a.tarFilePath

	if err := dockerAttestor.parseDockerManifest(ctx, manifestRaw); err != nil {
		log.Infof("FYI Docker manifest.json comparison failed: %v", err)
		return
	}

	imageID, err := dockerAttestor.Manifest[0].getImageID(ctx, a.tarFilePath)
	if err != nil {
		log.Infof("FYI Docker manifest.json comparison failed: %v", err)
		return
	}
	diffIDs, err := dockerAttestor.Manifest[0].getLayerDIFFIDs(ctx, a.tarFilePath)
	if err != nil {
		log.Infof("FYI Docker manifest.json comparison failed: %v", err)
		return
	}

	dockerAttestor.ImageID = imageID
	dockerAttestor.LayerDiffIDs = diffIDs
	dockerAttestor.ImageTags = dockerAttestor.Manifest[0].RepoTags

	output, err := json.MarshalIndent(dockerAttestor, "", "  ")
	if err != nil {
		log.Infof("FYI Docker manifest.json comparison failed: %v", err)
		return
	}
	log.Infof("FYI Docker manifest.json attestation:\n%s", output)
}

func (a *Attestor) parseDockerManifest(ctx *attestation.AttestationContext, manifestRaw []byte) error {
	a.ManifestRaw = manifestRaw

	manifestDigest, err := cryptoutil.CalculateDigestSetFromBytes(a.ManifestRaw, ctx.Hashes())
	if err != nil {
		return fmt.Errorf("calculate Docker manifest.json digest: %w", err)
	}

	a.ManifestDigest = manifestDigest

	if err := json.Unmarshal(a.ManifestRaw, &a.Manifest); err != nil {
		return fmt.Errorf("parse Docker manifest.json: %w", err)
	}

	if len(a.Manifest) == 0 {
		return fmt.Errorf("Docker manifest.json contains no image entries")
	}

	return nil
}

func (a *Attestor) parseOCIManifest(ctx *attestation.AttestationContext, indexRaw []byte, files map[string][]byte) error {
	type imageManifest struct {
		manifest Manifest
		raw      []byte
	}

	var images []imageManifest
	visited := make(map[string]struct{})

	// OCI indexes form a descriptor graph and may point to nested indexes.
	// Tags on a parent index are inherited by image manifests below it.
	var walkIndex func([]byte, []string, string) error
	walkIndex = func(raw []byte, inheritedTags []string, source string) error {
		var index v1.Index
		if err := json.Unmarshal(raw, &index); err != nil {
			return fmt.Errorf("parse OCI index %s: %w", source, err)
		}

		for descriptorIndex, descriptor := range index.Manifests {
			descriptorTags := tagsFromDescriptor(descriptor, inheritedTags)

			blobPath, err := descriptorPath(descriptor)
			if err != nil {
				return fmt.Errorf("resolve descriptor %d in OCI index %s: %w", descriptorIndex, source, err)
			}
			if _, ok := visited[blobPath]; ok {
				continue
			}
			visited[blobPath] = struct{}{}

			descriptorRaw, ok := files[blobPath]
			if !ok {
				return fmt.Errorf(
					"OCI index %s references missing %s descriptor blob %q",
					source,
					descriptor.MediaType,
					blobPath,
				)
			}

			switch descriptor.MediaType {
			// Recursively traverse the index.
			case v1.MediaTypeImageIndex:
				if err := walkIndex(descriptorRaw, descriptorTags, descriptor.Digest.String()); err != nil {
					return fmt.Errorf("follow nested OCI index %s: %w", descriptor.Digest, err)
				}
			// Parse the found manifest.
			case v1.MediaTypeImageManifest:
				var manifest v1.Manifest
				if err := json.Unmarshal(descriptorRaw, &manifest); err != nil {
					return fmt.Errorf("parse OCI image manifest %s: %w", descriptor.Digest, err)
				}

				// Artifacts and subject-linked manifests are not runnable images.
				if manifest.ArtifactType != "" || manifest.Subject != nil || manifest.Config.MediaType != v1.MediaTypeImageConfig {
					log.Debugf("(attestation/oci) skipping non-runnable manifest %s", descriptor.Digest)
					continue
				}

				configPath, err := descriptorPath(manifest.Config)
				if err != nil {
					return fmt.Errorf("resolve config descriptor in OCI image manifest %s: %w", descriptor.Digest, err)
				}

				layerPaths, runnable, err := parseLayers(manifest.Layers, descriptor.Digest.String())
				if err != nil {
					return err
				}
				if !runnable {
					log.Debugf("(attestation/oci) skipping non-runnable manifest %s", descriptor.Digest)
					continue
				}

				images = append(images, imageManifest{
					manifest: Manifest{
						Config:   configPath,
						RepoTags: descriptorTags,
						Layers:   layerPaths,
					},
					raw: descriptorRaw,
				})
			default:
				log.Debugf("(attestation/oci) skipping unsupported descriptor media type %q", descriptor.MediaType)
			}
		}

		return nil
	}

	if err := walkIndex(indexRaw, nil, "index.json"); err != nil {
		return err
	}
	if len(images) == 0 {
		return fmt.Errorf("OCI index graph contains no runnable image manifests")
	}

	a.Manifest = make([]Manifest, 0, len(images))
	for _, image := range images {
		a.Manifest = append(a.Manifest, image.manifest)
	}

	// v0.1 has singular raw/digest fields, so the first runnable image remains
	// the primary image while Manifest reports every runnable image discovered.
	a.ManifestRaw = images[0].raw
	manifestDigest, err := cryptoutil.CalculateDigestSetFromBytes(a.ManifestRaw, ctx.Hashes())
	if err != nil {
		return fmt.Errorf("calculate primary OCI image manifest digest: %w", err)
	}
	a.ManifestDigest = manifestDigest

	return nil
}

func descriptorPath(descriptor v1.Descriptor) (string, error) {
	if descriptor.Digest == "" {
		return "", fmt.Errorf("OCI descriptor has an empty digest")
	}
	if err := descriptor.Digest.Validate(); err != nil {
		return "", fmt.Errorf("OCI descriptor has an invalid digest %q: %w", descriptor.Digest, err)
	}

	algorithm := descriptor.Digest.Algorithm()
	encoded := descriptor.Digest.Encoded()

	return path.Join("blobs", algorithm.String(), encoded), nil
}

func tagsFromDescriptor(descriptor v1.Descriptor, inherited []string) []string {
	// containerd records a fully qualified image name, while the standard OCI
	// annotation commonly contains only the local reference name.
	if name := descriptor.Annotations["io.containerd.image.name"]; name != "" {
		return []string{name}
	}
	if name := descriptor.Annotations[v1.AnnotationRefName]; name != "" {
		return []string{name}
	}

	return append([]string(nil), inherited...)
}

func parseLayers(layers []v1.Descriptor, manifestDigest string) ([]string, bool, error) {
	layerPaths := make([]string, 0, len(layers))
	for layerIndex, layer := range layers {
		// Only OCI and Docker rootfs layers belong to runnable images.
		switch layer.MediaType {
		case v1.MediaTypeImageLayer,
			v1.MediaTypeImageLayerGzip,
			v1.MediaTypeImageLayerZstd,
			"application/vnd.docker.image.rootfs.diff.tar",
			"application/vnd.docker.image.rootfs.diff.tar.gzip",
			"application/vnd.docker.image.rootfs.foreign.diff.tar.gzip":
			layerPath, err := descriptorPath(layer)
			if err != nil {
				return nil, false, fmt.Errorf(
					"resolve layer descriptor %d in OCI image manifest %s: %w",
					layerIndex, manifestDigest, err,
				)
			}
			layerPaths = append(layerPaths, layerPath)
		default:
			return nil, false, nil
		}
	}

	return layerPaths, true, nil
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	subj := make(map[string]cryptoutil.DigestSet)
	subj[fmt.Sprintf("manifestdigest:%s", a.ManifestDigest[cryptoutil.DigestValue{Hash: crypto.SHA256}])] = a.ManifestDigest
	subj[fmt.Sprintf("tardigest:%s", a.TarDigest[cryptoutil.DigestValue{Hash: crypto.SHA256}])] = a.TarDigest
	subj[fmt.Sprintf("imageid:%s", a.ImageID[cryptoutil.DigestValue{Hash: crypto.SHA256}])] = a.ImageID

	// image tags
	for _, tag := range a.ImageTags {
		hash, err := cryptoutil.CalculateDigestSetFromBytes([]byte(tag), hashes)
		if err != nil {
			log.Debugf("(attestation/oci) error calculating image tag: %w", err)
			continue
		}
		subj[fmt.Sprintf("imagetag:%s", tag)] = hash
	}

	// diff ids
	for layer := range a.LayerDiffIDs {
		subj[fmt.Sprintf("layerdiffid%02d:%s", layer, a.LayerDiffIDs[layer][cryptoutil.DigestValue{Hash: crypto.SHA256}])] = a.LayerDiffIDs[layer]
	}
	return subj
}

func (m *Manifest) getLayerDIFFIDs(ctx *attestation.AttestationContext, tarFilePath string) ([]cryptoutil.DigestSet, error) {
	var layerDiffIDs []cryptoutil.DigestSet

	tarFile, err := os.Open(tarFilePath)
	if err != nil {
		return nil, err
	}
	defer tarFile.Close()

	tarReader := tar.NewReader(tarFile)
	for {
		h, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.FileInfo().IsDir() {
			continue
		}
		for _, layerFile := range m.Layers {
			if h.Name == layerFile {
				b := make([]byte, h.Size)

				_, err := tarReader.Read(b)
				if err != nil && err != io.EOF {
					return nil, err
				}

				contentType := http.DetectContentType(b)
				if contentType == "application/x-gzip" {
					breader, err := gzip.NewReader(bytes.NewReader(b))
					if err != nil {
						return nil, err
					}
					defer breader.Close()
					c, err := io.ReadAll(breader)
					if err != nil {
						return nil, err
					}
					layerDiffID, err := cryptoutil.CalculateDigestSetFromBytes(c, ctx.Hashes())
					if err != nil {
						return nil, err
					}
					layerDiffIDs = append(layerDiffIDs, layerDiffID)

				} else {
					layerDiffID, err := cryptoutil.CalculateDigestSetFromBytes(b, ctx.Hashes())
					if err != nil {
						return nil, err
					}
					layerDiffIDs = append(layerDiffIDs, layerDiffID)
				}

			}
		}
	}
	return layerDiffIDs, nil
}
