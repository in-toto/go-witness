// Copyright 2024 The Witness Contributors
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

// Package productarchive implements a post-product attestor that creates
// individual attestations for each output file/product. Unlike other attestors
// that create a single attestation, this attestor implements MultiExporter
// to create one attestation per archived product.
//
// Each attestation contains:
// - File metadata (permissions, timestamps, ownership, etc.)
// - File content (for files within size limit)
// - Cryptographic digests
//
// This allows for fine-grained attestations that can be individually
// verified and distributed without creating a single large attestation.
package productarchive

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/gobwas/glob"
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/registry"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "product-archive"
	Type    = "https://witness.dev/attestations/product-archive/v0.1"
	RunType = attestation.PostProductRunType

	defaultMaxFileSize = int64(100 * 1024 * 1024) // 100MB
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor      = &ProductArchive{}
	_ attestation.MultiExporter = &ProductArchive{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType,
		func() attestation.Attestor { return New() },
		registry.StringSliceConfigOption(
			"include-mime-types",
			"MIME types to include in the archive",
			[]string{},
			func(a attestation.Attestor, mimeTypes []string) (attestation.Attestor, error) {
				pa, ok := a.(*ProductArchive)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a product archive attestor", a)
				}
				WithIncludeMimeTypes(mimeTypes)(pa)
				return pa, nil
			},
		),
		registry.StringSliceConfigOption(
			"exclude-mime-types",
			"MIME types to exclude from the archive",
			[]string{},
			func(a attestation.Attestor, mimeTypes []string) (attestation.Attestor, error) {
				pa, ok := a.(*ProductArchive)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a product archive attestor", a)
				}
				WithExcludeMimeTypes(mimeTypes)(pa)
				return pa, nil
			},
		),
		registry.StringSliceConfigOption(
			"include-glob",
			"Glob patterns to include files",
			[]string{},
			func(a attestation.Attestor, patterns []string) (attestation.Attestor, error) {
				pa, ok := a.(*ProductArchive)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a product archive attestor", a)
				}
				WithIncludeGlob(patterns)(pa)
				return pa, nil
			},
		),
		registry.StringSliceConfigOption(
			"exclude-glob",
			"Glob patterns to exclude files",
			[]string{},
			func(a attestation.Attestor, patterns []string) (attestation.Attestor, error) {
				pa, ok := a.(*ProductArchive)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a product archive attestor", a)
				}
				WithExcludeGlob(patterns)(pa)
				return pa, nil
			},
		),
		registry.IntConfigOption(
			"max-file-size",
			"Maximum file size to include (in bytes)",
			int(defaultMaxFileSize),
			func(a attestation.Attestor, size int) (attestation.Attestor, error) {
				pa, ok := a.(*ProductArchive)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a product archive attestor", a)
				}
				WithMaxFileSize(int64(size))(pa)
				return pa, nil
			},
		),
	)
}

type Option func(*ProductArchive)

func WithIncludeMimeTypes(mimeTypes []string) Option {
	return func(pa *ProductArchive) {
		pa.includeMimeTypes = mimeTypes
	}
}

func WithExcludeMimeTypes(mimeTypes []string) Option {
	return func(pa *ProductArchive) {
		pa.excludeMimeTypes = mimeTypes
	}
}

func WithIncludeGlob(patterns []string) Option {
	return func(pa *ProductArchive) {
		pa.includeGlob = patterns
	}
}

func WithExcludeGlob(patterns []string) Option {
	return func(pa *ProductArchive) {
		pa.excludeGlob = patterns
	}
}

func WithMaxFileSize(size int64) Option {
	return func(pa *ProductArchive) {
		pa.maxFileSize = size
	}
}

type FileMetadata struct {
	Mode       uint32            `json:"mode"`                 // File permissions
	UID        uint32            `json:"uid"`                  // User ID
	GID        uint32            `json:"gid"`                  // Group ID
	Size       int64             `json:"size"`                 // File size in bytes
	ModTime    int64             `json:"modTime"`              // Modification time (unix timestamp)
	AccessTime int64             `json:"accessTime"`           // Access time (unix timestamp)
	ChangeTime int64             `json:"changeTime"`           // Change time (unix timestamp)
	BirthTime  *int64            `json:"birthTime,omitempty"`  // Creation time (if available)
	Inode      uint64            `json:"inode"`                // Inode number
	Nlink      uint64            `json:"nlink"`                // Number of hard links
	IsDir      bool              `json:"isDir"`                // Is directory
	IsRegular  bool              `json:"isRegular"`            // Is regular file
	IsSymlink  bool              `json:"isSymlink"`            // Is symbolic link
	LinkTarget string            `json:"linkTarget,omitempty"` // Symlink target
	Xattrs     map[string]string `json:"xattrs,omitempty"`     // Extended attributes
}

type ArchivedProduct struct {
	Name     string               `json:"name"`
	Path     string               `json:"path"`
	MimeType string               `json:"mimeType"`
	Digest   cryptoutil.DigestSet `json:"digest"`
	Content  []byte               `json:"content,omitempty"`
	Metadata FileMetadata         `json:"metadata"`
}

type ProductArchive struct {
	products         []ArchivedProduct
	allProducts      map[string]attestation.Product
	includeMimeTypes []string
	excludeMimeTypes []string
	includeGlob      []string
	excludeGlob      []string
	maxFileSize      int64
	workingDir       string
}

func New(opts ...Option) *ProductArchive {
	pa := &ProductArchive{
		maxFileSize: defaultMaxFileSize,
		products:    []ArchivedProduct{},
	}

	for _, opt := range opts {
		opt(pa)
	}

	return pa
}

func (pa *ProductArchive) Name() string {
	return Name
}

func (pa *ProductArchive) Type() string {
	return Type
}

func (pa *ProductArchive) RunType() attestation.RunType {
	return RunType
}

func (pa *ProductArchive) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(struct {
		Products []ArchivedProduct `json:"products"`
	}{})
}

func (pa *ProductArchive) Export() bool {
	// Always export this attestor separately to avoid bloating the attestation collection
	return true
}

// collectFileMetadata gathers comprehensive metadata about a file
func collectFileMetadata(path string, info os.FileInfo) (FileMetadata, error) {
	metadata := FileMetadata{
		Size:      info.Size(),
		Mode:      uint32(info.Mode()),
		ModTime:   info.ModTime().Unix(),
		IsDir:     info.IsDir(),
		IsRegular: info.Mode().IsRegular(),
		IsSymlink: info.Mode()&os.ModeSymlink != 0,
	}

	// Get system-specific metadata
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		metadata.UID = stat.Uid
		metadata.GID = stat.Gid
		metadata.Inode = stat.Ino
		metadata.Nlink = uint64(stat.Nlink)

		// Platform-specific times are handled in platform files
		setFileTimes(&metadata, stat)

		// Birth time (creation time) is platform-specific
		if birthTime := getBirthTime(stat); birthTime != nil {
			metadata.BirthTime = birthTime
		}
	}

	// Handle symlinks
	if metadata.IsSymlink {
		target, err := os.Readlink(path)
		if err == nil {
			metadata.LinkTarget = target
		}
	}

	// Get extended attributes (platform-specific)
	xattrs, err := getXattrs(path)
	if err == nil && len(xattrs) > 0 {
		metadata.Xattrs = xattrs
	}

	return metadata, nil
}

// readFileContent reads file content if it's within the size limit.
// For files larger than maxSize, it returns nil content without error.
func readFileContent(path string, maxSize int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	// If file is larger than maxSize, don't read content
	if info.Size() > maxSize {
		return nil, nil
	}

	// For files within size limit, read the content
	content := make([]byte, info.Size())
	_, err = io.ReadFull(file, content)
	if err != nil {
		return nil, err
	}

	return content, nil
}

func (pa *ProductArchive) Attest(ctx *attestation.AttestationContext) error {
	pa.workingDir = ctx.WorkingDir()
	pa.allProducts = ctx.Products()

	// Compile glob patterns
	includeGlobs := make([]glob.Glob, 0, len(pa.includeGlob))
	for _, pattern := range pa.includeGlob {
		g, err := glob.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid include glob pattern %s: %w", pattern, err)
		}
		includeGlobs = append(includeGlobs, g)
	}

	excludeGlobs := make([]glob.Glob, 0, len(pa.excludeGlob))
	for _, pattern := range pa.excludeGlob {
		g, err := glob.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid exclude glob pattern %s: %w", pattern, err)
		}
		excludeGlobs = append(excludeGlobs, g)
	}

	// Process products based on filters
	for name, product := range pa.allProducts {
		filePath := filepath.Join(pa.workingDir, name)

		// Check glob patterns
		if !pa.matchesGlobPatterns(name, includeGlobs, excludeGlobs) {
			continue
		}

		// Check MIME type filters
		if !pa.matchesMimeTypes(product.MimeType) {
			continue
		}

		// Get file info and metadata
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			log.Warnf("Could not stat file %s: %v", filePath, err)
			continue
		}

		// Skip files that exceed max size
		if fileInfo.Size() > pa.maxFileSize {
			log.Debugf("Skipping file %s: size %d exceeds max %d", name, fileInfo.Size(), pa.maxFileSize)
			continue
		}

		// Collect file metadata
		metadata, err := collectFileMetadata(filePath, fileInfo)
		if err != nil {
			log.Warnf("Could not collect metadata for file %s: %v", filePath, err)
			// Continue with partial metadata
		}

		// Read file content (now we know it's within size limit)
		content, err := readFileContent(filePath, pa.maxFileSize)
		if err != nil {
			log.Warnf("Could not read file %s: %v", filePath, err)
		}

		archivedProduct := ArchivedProduct{
			Name:     name,
			Path:     filePath,
			MimeType: product.MimeType,
			Digest:   product.Digest,
			Content:  content,
			Metadata: metadata,
		}

		pa.products = append(pa.products, archivedProduct)
	}

	log.Infof("Archived %d products out of %d total", len(pa.products), len(pa.allProducts))
	return nil
}

func (pa *ProductArchive) matchesGlobPatterns(name string, includeGlobs, excludeGlobs []glob.Glob) bool {
	// If exclude patterns are specified and match, exclude the file
	for _, g := range excludeGlobs {
		if g.Match(name) {
			return false
		}
	}

	// If no include patterns specified, include by default
	if len(includeGlobs) == 0 {
		return true
	}

	// If include patterns are specified, at least one must match
	for _, g := range includeGlobs {
		if g.Match(name) {
			return true
		}
	}

	return false
}

func (pa *ProductArchive) matchesMimeTypes(mimeType string) bool {
	// If exclude MIME types are specified and match, exclude the file
	for _, excludeType := range pa.excludeMimeTypes {
		if mimeType == excludeType {
			return false
		}
	}

	// If no include MIME types specified, include by default
	if len(pa.includeMimeTypes) == 0 {
		return true
	}

	// If include MIME types are specified, must match one
	for _, includeType := range pa.includeMimeTypes {
		if mimeType == includeType {
			return true
		}
	}

	return false
}

func (pa *ProductArchive) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Products []ArchivedProduct `json:"products"`
	}{
		Products: pa.products,
	})
}

func (pa *ProductArchive) UnmarshalJSON(data []byte) error {
	var temp struct {
		Products []ArchivedProduct `json:"products"`
	}

	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	pa.products = temp.Products
	return nil
}

// ExportedAttestations returns individual attestations for each archived product
func (pa *ProductArchive) ExportedAttestations() []attestation.ExportedAttestation {
	attestations := make([]attestation.ExportedAttestation, 0, len(pa.products))

	for _, product := range pa.products {
		// Create a single-product attestation
		singleProduct := struct {
			Products []ArchivedProduct `json:"products"`
		}{
			Products: []ArchivedProduct{product},
		}

		// Create subjects for this specific product
		subjects := make(map[string]cryptoutil.DigestSet)
		subjects[fmt.Sprintf("file:%s", product.Name)] = product.Digest

		attestations = append(attestations, attestation.ExportedAttestation{
			Predicate:     singleProduct,
			PredicateType: Type,
			Subjects:      subjects,
			Name:          product.Name,
		})
	}

	return attestations
}
