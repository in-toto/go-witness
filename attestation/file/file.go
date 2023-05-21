// Copyright 2021 The Witness Contributors
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

package file

import (
	"crypto"
	"encoding/json"
	"fmt"
	"github.com/fkautz/omnitrail-go"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/edwarnicke/gitoid"
	"github.com/testifysec/go-witness/cryptoutil"
	"github.com/testifysec/go-witness/log"
)

// recordArtifacts will walk basePath and record the digests of each file with each of the functions in hashes.
// If file already exists in baseArtifacts and the two artifacts are equal the artifact will not be in the
// returned map of artifacts.
func RecordArtifacts(basePath string, baseArtifacts map[string]cryptoutil.DigestSet, hashes []crypto.Hash, visitedSymlinks map[string]struct{}) (map[string]cryptoutil.DigestSet, error) {
	artifacts := make(map[string]cryptoutil.DigestSet)
	trail := omnitrail.New(omnitrail.WithSha1(), omnitrail.WithSha256())
	err := filepath.Walk(basePath, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if err := trail.Add(path); err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(basePath, path)
		if err != nil {
			return err
		}

		if info.Mode()&fs.ModeSymlink != 0 {
			// if this is a symlink, eval the true path and eval any artifacts in the symlink. we record every symlink we've visited to prevent infinite loops
			linkedPath, err := filepath.EvalSymlinks(path)
			if os.IsNotExist(err) {
				log.Debugf("(file) broken symlink detected: %v", path)
				return nil
			} else if err != nil {
				return err
			}

			if _, ok := visitedSymlinks[linkedPath]; ok {
				return nil
			}

			visitedSymlinks[linkedPath] = struct{}{}
			symlinkedArtifacts, err := RecordArtifacts(linkedPath, baseArtifacts, hashes, visitedSymlinks)
			if err != nil {
				return err
			}

			for artifactPath, artifact := range symlinkedArtifacts {
				// all artifacts in the symlink should be recorded relative to our basepath
				joinedPath := filepath.Join(relPath, artifactPath)
				if shouldRecord(joinedPath, artifact, baseArtifacts) {
					artifacts[filepath.Join(relPath, artifactPath)] = artifact
				}
			}

			return nil
		}

		artifact, err := cryptoutil.CalculateDigestSetFromFile(path, hashes)
		if err != nil {
			return err
		}

		fileReader, err := os.Open(path)
		if err != nil {
			return err
		}

		goidSha1, err := gitoid.New(fileReader)
		if err != nil {
			return err
		}

		goidSha256, err := gitoid.New(fileReader, gitoid.WithSha256())
		if err != nil {
			return err
		}

		artifact[cryptoutil.DigestValue{
			Hash:   crypto.SHA1,
			GitOID: true,
		}] = goidSha1.URI()

		artifact[cryptoutil.DigestValue{
			Hash:   crypto.SHA256,
			GitOID: true,
		}] = goidSha256.URI()

		if shouldRecord(relPath, artifact, baseArtifacts) {
			artifacts[relPath] = artifact
		}

		return nil
	})

	j, e := json.MarshalIndent(trail, "", "  ")
	if e != nil {
		return nil, e
	}

	fmt.Println("sha1")
	adgs := trail.Sha1ADGs()
	for k, v := range adgs {
		fmt.Printf("%s:\n%s\n\n", k, v)
	}

	fmt.Println("sha256")
	adgs = trail.Sha256ADGs()
	for k, v := range adgs {
		fmt.Printf("%s:\n%s\n\n", k, v)
	}

	fmt.Println(string(j))

	return artifacts, err
}

// shouldRecord determines whether artifact should be recorded.
// if the artifact is already in baseArtifacts, check if it's changed
// if it is not equal to the existing artifact, return true, otherwise return false
func shouldRecord(path string, artifact cryptoutil.DigestSet, baseArtifacts map[string]cryptoutil.DigestSet) bool {
	if previous, ok := baseArtifacts[path]; ok && artifact.Equal(previous) {
		return false
	}
	return true
}
