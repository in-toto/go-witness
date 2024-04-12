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
	"io/fs"
	"os"
	"path/filepath"

	"github.com/gobwas/glob"
	"github.com/gobwas/glob/match"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
)

// recordArtifacts will walk basePath and record the digests of each file with each of the functions in hashes.
// If file already exists in baseArtifacts and the two artifacts are equal the artifact will not be in the
// returned map of artifacts.
func RecordArtifacts(basePath string, baseArtifacts map[string]cryptoutil.DigestSet, hashes []cryptoutil.DigestValue, visitedSymlinks map[string]struct{}, processWasTraced bool, openedFiles map[string]bool, includeGlob glob.Glob, excludeGlob glob.Glob) (map[string]cryptoutil.DigestSet, error) {
	artifacts := make(map[string]cryptoutil.DigestSet)
	err := filepath.Walk(basePath, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
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
			symlinkedArtifacts, err := RecordArtifacts(linkedPath, baseArtifacts, hashes, visitedSymlinks, processWasTraced, openedFiles, includeGlob, excludeGlob)
			if err != nil {
				return err
			}

			for artifactPath, artifact := range symlinkedArtifacts {
				// all artifacts in the symlink should be recorded relative to our basepath
				joinedPath := filepath.Join(relPath, artifactPath)

				if shouldRecord(joinedPath, artifact, baseArtifacts, processWasTraced, openedFiles, includeGlob, excludeGlob) {
					artifacts[filepath.Join(relPath, artifactPath)] = artifact
				}
			}

			return nil
		}

		artifact, err := cryptoutil.CalculateDigestSetFromFile(path, hashes)
		if err != nil {
			return err
		}

		if shouldRecord(relPath, artifact, baseArtifacts, processWasTraced, openedFiles, includeGlob, excludeGlob) {
			artifacts[relPath] = artifact
		}

		return nil
	})

	return artifacts, err
}

// shouldRecord determines whether artifact should be recorded.
// if the process was traced and the artifact was not one of the opened files, return false
// if the artifact is already in baseArtifacts, check if it's changed
// if it is not equal to the existing artifact, return true, otherwise return false
func shouldRecord(path string, artifact cryptoutil.DigestSet, baseArtifacts map[string]cryptoutil.DigestSet, processWasTraced bool, openedFiles map[string]bool, includeGlob glob.Glob, excludeGlob glob.Glob) bool {
	superInclude := false
	if _, ok := includeGlob.(match.Super); ok {
		superInclude = true
	}

	includePath := true
	if excludeGlob != nil && excludeGlob.Match(path) {
		includePath = false
	}
	if !(superInclude && !includePath) && includeGlob != nil && includeGlob.Match(path) {
		includePath = true
	}

	if !includePath {
		return false
	}

	if _, ok := openedFiles[path]; !ok && processWasTraced {
		return false
	}

	if previous, ok := baseArtifacts[path]; ok && artifact.Equal(previous) {
		return false
	}
	return true
}
