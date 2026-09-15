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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/gobwas/glob"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
)

// recordArtifacts will walk basePath and record the digests of each file with each of the functions in hashes.
// If file already exists in baseArtifacts and the two artifacts are equal the artifact will not be in the
// returned map of artifacts.
func RecordArtifacts(basePath string, baseArtifacts map[string]cryptoutil.DigestSet, hashes []cryptoutil.DigestValue, visitedSymlinks map[string]struct{}, processWasTraced bool, openedFiles map[string]bool, dirHashGlob []glob.Glob) (map[string]cryptoutil.DigestSet, error) {
	// Preserve the original attested root across symlink recursion so the boundary check always
	// compares against the tree the caller asked to attest, not the narrower base of a followed
	// in-tree symlink.
	return recordArtifacts(basePath, basePath, baseArtifacts, hashes, visitedSymlinks, processWasTraced, openedFiles, dirHashGlob)
}

func recordArtifacts(basePath, root string, baseArtifacts map[string]cryptoutil.DigestSet, hashes []cryptoutil.DigestValue, visitedSymlinks map[string]struct{}, processWasTraced bool, openedFiles map[string]bool, dirHashGlob []glob.Glob) (map[string]cryptoutil.DigestSet, error) {
	artifacts := make(map[string]cryptoutil.DigestSet)
	err := filepath.Walk(basePath, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(basePath, path)
		if err != nil {
			return err
		}

		if info.IsDir() {
			dirHashMatch := false
			for _, globItem := range dirHashGlob {
				if !dirHashMatch && globItem.Match(relPath) {
					dirHashMatch = true
				}
			}

			if dirHashMatch {
				// Directory hashing follows symlinks when reading file contents, which would
				// otherwise re-introduce the out-of-tree read the normal walk guards against.
				// Refuse to hash a directory that contains a symlink resolving outside the
				// attested path rather than silently hashing the external target.
				escapes, err := dirHasEscapingSymlink(path, root)
				if err != nil {
					return err
				}
				if escapes {
					return fmt.Errorf("(file) refusing to hash directory %v: it contains a symlink resolving outside the attested path", path)
				}

				dir, err := cryptoutil.CalculateDigestSetFromDir(path, hashes)

				if err != nil {
					return err
				}

				artifacts[relPath+string(os.PathSeparator)] = dir
				return filepath.SkipDir
			}

			return nil
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

			// Do not follow a symlink whose target resolves outside the tree being attested.
			// Otherwise a symlink placed in the attested directory could cause out-of-tree files
			// (secrets, system files) to be opened, hashed, and recorded into the attestation.
			within, err := pathWithinBase(root, linkedPath)
			if err != nil {
				return err
			}
			if !within {
				log.Debugf("(file) skipping symlink %v: target %v resolves outside the attested path", path, linkedPath)
				return nil
			}

			if _, ok := visitedSymlinks[linkedPath]; ok {
				return nil
			}

			visitedSymlinks[linkedPath] = struct{}{}
			symlinkedArtifacts, err := recordArtifacts(linkedPath, root, baseArtifacts, hashes, visitedSymlinks, processWasTraced, openedFiles, dirHashGlob)
			if err != nil {
				return err
			}

			for artifactPath, artifact := range symlinkedArtifacts {
				// all artifacts in the symlink should be recorded relative to our basepath
				joinedPath := filepath.Join(relPath, artifactPath)
				if shouldRecord(joinedPath, artifact, baseArtifacts, processWasTraced, openedFiles) {
					artifacts[filepath.Join(relPath, artifactPath)] = artifact
				}
			}

			return nil
		}

		artifact, err := cryptoutil.CalculateDigestSetFromFile(path, hashes)
		if err != nil {
			return err
		}

		if shouldRecord(relPath, artifact, baseArtifacts, processWasTraced, openedFiles) {
			artifacts[relPath] = artifact
		}

		return nil
	})

	return artifacts, err
}

// pathWithinBase reports whether resolvedTarget (an already symlink-resolved, absolute-or-relative
// path) is contained within basePath. basePath is canonicalized with EvalSymlinks so the comparison
// is not defeated by symlinked path components (for example /tmp -> /private/tmp on macOS). It is
// used to ensure the file attestor does not follow a symlink outside the tree being attested.
func pathWithinBase(basePath, resolvedTarget string) (bool, error) {
	absBase, err := filepath.Abs(basePath)
	if err != nil {
		return false, err
	}
	if canonicalBase, err := filepath.EvalSymlinks(absBase); err == nil {
		absBase = canonicalBase
	}

	absTarget, err := filepath.Abs(resolvedTarget)
	if err != nil {
		return false, err
	}

	rel, err := filepath.Rel(absBase, absTarget)
	if err != nil {
		return false, nil
	}

	// The target is within base unless the relative path escapes it with "..".
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return false, nil
	}

	return true, nil
}

// dirHasEscapingSymlink reports whether dir contains any symlink whose target resolves outside
// basePath. It is used to refuse directory hashing when an out-of-tree symlink is present, since the
// directory-hash path follows symlinks while reading and cannot selectively exclude them. Broken
// symlinks are ignored.
func dirHasEscapingSymlink(dir, basePath string) (bool, error) {
	found := false
	err := filepath.Walk(dir, func(p string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			return nil
		}

		resolved, err := filepath.EvalSymlinks(p)
		if os.IsNotExist(err) {
			return nil
		} else if err != nil {
			return err
		}

		within, err := pathWithinBase(basePath, resolved)
		if err != nil {
			return err
		}
		if !within {
			found = true
		}
		return nil
	})

	return found, err
}

// shouldRecord determines whether artifact should be recorded.
// if the process was traced and the artifact was not one of the opened files, return false
// if the artifact is already in baseArtifacts, check if it's changed
// if it is not equal to the existing artifact, return true, otherwise return false
func shouldRecord(path string, artifact cryptoutil.DigestSet, baseArtifacts map[string]cryptoutil.DigestSet, processWasTraced bool, openedFiles map[string]bool) bool {
	if _, ok := openedFiles[path]; !ok && processWasTraced {
		return false
	}
	if previous, ok := baseArtifacts[path]; ok && artifact.Equal(previous) {
		return false
	}
	return true
}
