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
	"runtime"
	"sync"

	"github.com/gobwas/glob"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
)

// fileJob represents a file hashing job for the worker pool
type fileJob struct {
	path    string
	relPath string
}

// fileResult represents the result of a file hashing job
type fileResult struct {
	relPath string
	digest  cryptoutil.DigestSet
	err     error
}

// RecordArtifacts will walk basePath and record the digests of each file with each of the functions in hashes.
// If file already exists in baseArtifacts and the two artifacts are equal the artifact will not be in the
// returned map of artifacts. File hashing is performed in parallel using a worker pool for improved performance.
func RecordArtifacts(basePath string, baseArtifacts map[string]cryptoutil.DigestSet, hashes []cryptoutil.DigestValue, visitedSymlinks map[string]struct{}, processWasTraced bool, openedFiles map[string]bool, dirHashGlob []glob.Glob) (map[string]cryptoutil.DigestSet, error) {
	artifacts := make(map[string]cryptoutil.DigestSet)

	// Determine number of workers based on available CPUs
	numWorkers := max(runtime.GOMAXPROCS(0), 1)

	// Create channels for job distribution and result collection
	jobs := make(chan fileJob, numWorkers*2)
	results := make(chan fileResult, numWorkers*2)

	// WaitGroup to track when all workers are done
	var wg sync.WaitGroup

	// Start worker goroutines
	for range numWorkers {
		wg.Go(func() {
			for job := range jobs {
				digest, err := cryptoutil.CalculateDigestSetFromFile(job.path, hashes)
				results <- fileResult{
					relPath: job.relPath,
					digest:  digest,
					err:     err,
				}
			}
		})
	}

	// Channel to signal walk completion and capture walk error
	walkDone := make(chan error, 1)

	// Start the directory walk in a goroutine
	go func() {
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
					dir, err := cryptoutil.CalculateDigestSetFromDir(path, hashes)
					if err != nil {
						return err
					}

					// Send directory hash result directly
					results <- fileResult{
						relPath: relPath + string(os.PathSeparator),
						digest:  dir,
						err:     nil,
					}
					return filepath.SkipDir
				}

				return nil
			}

			if info.Mode()&fs.ModeSymlink != 0 {
				// Handle symlinks: eval the true path and process artifacts
				linkedPath, err := filepath.EvalSymlinks(path)
				if os.IsNotExist(err) {
					log.Debugf("(file) broken symlink detected: %v", path)
					return nil
				} else if err != nil {
					return err
				}

				// Avoid cycles by tracking visited symlinks
				if _, ok := visitedSymlinks[linkedPath]; ok {
					return nil
				}

				visitedSymlinks[linkedPath] = struct{}{}

				// Recursively process symlinked directory/file
				// Note: This recursive call handles its own parallelization
				symlinkedArtifacts, err := RecordArtifacts(linkedPath, baseArtifacts, hashes, visitedSymlinks, processWasTraced, openedFiles, dirHashGlob)
				if err != nil {
					return err
				}

				for artifactPath, artifact := range symlinkedArtifacts {
					// Send symlink artifacts to results channel
					// The collector will apply shouldRecord filtering
					results <- fileResult{
						relPath: filepath.Join(relPath, artifactPath),
						digest:  artifact,
						err:     nil,
					}
				}

				return nil
			}

			// Regular file - send to worker pool
			jobs <- fileJob{
				path:    path,
				relPath: relPath,
			}

			return nil
		})

		// Close jobs channel to signal workers to finish
		close(jobs)
		walkDone <- err
	}()

	// Wait for workers to complete, then close results channel
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var walkErr error

	// Read results until the results channel is closed
	for result := range results {
		if result.err != nil {
			// Store first error encountered
			if walkErr == nil {
				walkErr = result.err
			}
			continue
		}

		if shouldRecord(result.relPath, result.digest, baseArtifacts, processWasTraced, openedFiles) {
			artifacts[result.relPath] = result.digest
		}
	}

	// Check for walk error
	if err := <-walkDone; err != nil && walkErr == nil {
		walkErr = err
	}

	return artifacts, walkErr
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
