// Copyright 2023 The Witness Contributors
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

package git

import (
	"crypto"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/edwarnicke/gitoid"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/require"
	"github.com/testifysec/go-witness/attestation"
	"github.com/testifysec/go-witness/cryptoutil"
)

func TestNew(t *testing.T) {
	attestor := New()
	require.NotNil(t, attestor, "Expected a new attestor")
	require.NotNil(t, attestor.Status, "Expected a map for Status")
}

func TestNameTypeRunType(t *testing.T) {
	attestor := New()
	require.Equal(t, Name, attestor.Name(), "Expected the attestor's name")
	require.Equal(t, Type, attestor.Type(), "Expected the attestor's type")
	require.Equal(t, RunType, attestor.RunType(), "Expected the attestor's run type")
}

func TestRun(t *testing.T) {
	attestor := New()

	_, dir, cleanup := createTestRepo(t)
	defer cleanup()

	ctx, err := attestation.NewContext([]attestation.Attestor{attestor}, attestation.WithWorkingDir(dir))
	require.NoError(t, err, "Expected no error from NewContext")

	err = ctx.RunAttestors()
	require.NoError(t, err, "Expected no error from RunAttestors")

	require.Empty(t, attestor.ParentHashes, "Expected the parent hashes to be set")

	createTestCommit(t, dir, "Test commit")
	createTestRefs(t, dir)
	createAnnotatedTagOnHead(t, dir)
	err = ctx.RunAttestors()

	// Check that the attestor has the expected values

	require.NoError(t, err, "Expected no error from attestation")
	require.NotEmpty(t, attestor.CommitHash, "Expected the commit hash to be set")
	require.NotEmpty(t, attestor.Author, "Expected the author to be set")
	require.NotEmpty(t, attestor.AuthorEmail, "Expected the author's email to be set")
	require.NotEmpty(t, attestor.CommitterName, "Expected the committer to be set")
	require.NotEmpty(t, attestor.CommitterEmail, "Expected the committer's email to be set")
	require.NotEmpty(t, attestor.CommitDate, "Expected the commit date to be set")
	require.NotEmpty(t, attestor.CommitMessage, "Expected the commit message to be set")
	require.NotEmpty(t, attestor.CommitDigest, "Expected the commit digest to be set")
	require.NotEmpty(t, attestor.TreeHash, "Expected the tree hash to be set")
	require.NotEmpty(t, attestor.ParentHashes, "Expected the parent hashes to be set")

	subjects := attestor.Subjects()
	require.NotNil(t, subjects, "Expected subjects to be non-nil")

	// Test for the existence of subjects
	require.Contains(t, subjects, fmt.Sprintf("commithash:%v", attestor.CommitHash), "Expected commithash subject to exist")
	require.Contains(t, subjects, fmt.Sprintf("authoremail:%v", attestor.AuthorEmail), "Expected authoremail subject to exist")
	require.Contains(t, subjects, fmt.Sprintf("committeremail:%v", attestor.CommitterEmail), "Expected committeremail subject to exist")

	for _, parentHash := range attestor.ParentHashes {
		subjectName := fmt.Sprintf("parenthash:%v", parentHash)
		require.Contains(t, subjects, subjectName, "Expected parent hash subject to exist")
	}

	backrefs := attestor.BackRefs()
	require.NotNil(t, backrefs, "Expected backrefs to be non-nil")

	subjectName := fmt.Sprintf("commithash:%v", attestor.CommitHash)
	require.Contains(t, backrefs, subjectName, "Expected commithash backref to exist")

	ds := backrefs[subjectName]
	require.NotNil(t, ds, "Expected a digest set for the commithash backref")

	// Test for the existence of a SHA1 digest in the digest set
	var found bool
	for d, v := range ds {
		if d.Hash == crypto.SHA1 {
			found = true
			require.Equal(t, d.GitOID, false, "Expected GitOID to be false")
			require.Equal(t, v, attestor.CommitHash, "Expected the correct value for the SHA1 digest")
		}
	}

	require.True(t, found, "Expected a SHA1 digest in the digest set")

	subRefName := "refs/tags/v1.0.0-lightweight"
	require.NoError(t, err, "Expected lightweight tag to exist")
	require.Contains(t, attestor.Refs, subRefName, "Expected lightweight tag ref to be attested")

	subRefName = "refs/heads/my-feature-branch"
	require.NoError(t, err, "Expected branch to exist")
	require.Contains(t, attestor.Refs, subRefName, "Expected branch ref to be attested")

	subRefName = "refs/heads/my-feature-branch@123"
	require.NoError(t, err, "Expected ref with special characters to exist")
	require.Contains(t, attestor.Refs, subRefName, "Expected ref with special characters to be attested")

	// Test the annotated tag contents
	tags := attestor.Tags
	require.NotNil(t, tags, "Expected tags to be non-nil")

	//we should have 1 tag
	require.Len(t, tags, 1, "Expected 1 tag")

	//get the tag object
	tagObject := tags[0]

	require.NoError(t, err, "Expected no error from getTagObject")
	require.Equal(t, "v1.0.0-test", tagObject.Name)
	require.Equal(t, "example tag message\n", tagObject.Message)
	require.Equal(t, "John Doe", tagObject.TaggerName)
	require.Equal(t, "tagger@example.com", tagObject.TaggerEmail)

	//test the file changes with no parent
	require.Len(t, attestor.FileChanges, 1, "Expected 1 file change")

	//calculate the file hash
	digestSet, err := gitOIDDigestSetFromFile(filepath.Join(dir, "test.txt"))
	require.NoError(t, err, "Expected no error from gitOIDDigestSetFromFile")

	//make sure the hash is correct
	require.Equal(t, digestSet, attestor.FileChanges[0].Current.Digest)

}

func createTestRepo(t *testing.T) (*git.Repository, string, func()) {
	// Create a temporary directory for the test repository
	tmpDir, err := os.MkdirTemp("", "test-repo")
	require.NoError(t, err)

	// Initialize a new Git repository in the temporary directory
	repo, err := git.PlainInit(tmpDir, false)
	require.NoError(t, err)

	// Create a new file in the repository
	filePath := filepath.Join(tmpDir, "test.txt")
	file, err := os.Create(filePath)
	require.NoError(t, err)
	_, err = file.WriteString("Test file")
	require.NoError(t, err)
	err = file.Close()
	require.NoError(t, err)

	// Add the new file to the repository
	worktree, err := repo.Worktree()
	require.NoError(t, err)
	_, err = worktree.Add("test.txt")
	require.NoError(t, err)

	// Commit the new file to the repository
	_, err = worktree.Commit("Initial commit", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test User",
			Email: "test@example.com",
			When:  time.Now(),
		},
	})
	require.NoError(t, err)

	// Return the test repository, the path to the test repository, and a cleanup function
	return repo, tmpDir, func() {
		err := os.RemoveAll(tmpDir)
		require.NoError(t, err)
	}
}
func createTestCommit(t *testing.T, repoPath string, message string) {
	// Open the Git repository
	repo, err := git.PlainOpen(repoPath)
	require.NoError(t, err)

	// Get the HEAD reference
	headRef, err := repo.Head()
	require.NoError(t, err)

	// Get the commit that the HEAD reference points to
	commit, err := repo.CommitObject(headRef.Hash())
	require.NoError(t, err)

	// Create a new file in the repository with a random string
	randStr := fmt.Sprintf("%d", rand.Int())
	filePath := filepath.Join(repoPath, "test.txt")
	file, err := os.Create(filePath)
	require.NoError(t, err)
	_, err = file.WriteString(randStr)
	require.NoError(t, err)
	err = file.Close()
	require.NoError(t, err)

	// Add the new file to the repository
	worktree, err := repo.Worktree()
	require.NoError(t, err)
	_, err = worktree.Add("test.txt")
	require.NoError(t, err)

	// Commit the new file to the repository use current commit as parent
	_, err = worktree.Commit(message, &git.CommitOptions{
		All:       false,
		Author:    &object.Signature{Name: "Test User", Email: "test@example.com", When: time.Now()},
		Committer: &object.Signature{Name: "Test User", Email: "test@example.com", When: time.Now()},
		Parents:   []plumbing.Hash{commit.Hash},
	})
	require.NoError(t, err)
}

func createTestRefs(t *testing.T, dir string) {
	// Open the Git repository
	repo, err := git.PlainOpen(dir)
	require.NoError(t, err)

	// Get the HEAD reference
	headRef, err := repo.Head()
	require.NoError(t, err)

	// Get the commit that the HEAD reference points to
	hash := headRef.Hash()

	// Create a new branch ref pointing to the specified commit hash
	branchRef := plumbing.NewBranchReferenceName("my-feature-branch")
	err = repo.Storer.SetReference(plumbing.NewHashReference(branchRef, hash))
	require.NoError(t, err)

	// Create a new lightweight tag pointing to the specified commit hash
	lightweightTagName := "v1.0.0-lightweight"
	err = repo.Storer.SetReference(plumbing.NewHashReference(plumbing.ReferenceName("refs/tags/"+lightweightTagName), hash))
	require.NoError(t, err)

	// Create a new ref with a special character in the name
	specialCharRef := plumbing.NewHashReference(plumbing.ReferenceName("refs/heads/my-feature-branch@123"), hash)
	err = repo.Storer.SetReference(specialCharRef)
	require.NoError(t, err)
}

func createAnnotatedTagOnHead(t *testing.T, path string) {
	// Open the Git repository.
	repo, err := git.PlainOpen(path)
	require.NoError(t, err)

	// Get the HEAD reference.
	headRef, err := repo.Head()
	require.NoError(t, err)

	// Get the commit that the HEAD reference points to.
	commit, err := repo.CommitObject(headRef.Hash())
	require.NoError(t, err)

	_, err = repo.CreateTag("v1.0.0-test", commit.Hash, &git.CreateTagOptions{
		Tagger: &object.Signature{
			Name: "John Doe",

			Email: "tagger@example.com",
			When:  time.Now(),
		},
		Message: "example tag message",
	})

	require.NoError(t, err)
}

func TestGetFileChangesInCommit(t *testing.T) {
	// Create a new test repository
	repo, repoPath, cleanup := createTestRepo(t)
	defer cleanup()

	// Create a new commit with changes to the test file
	createTestCommit(t, repoPath, "Test commit")

	// Get the commit hash of the new commit
	ref, err := repo.Head()
	require.NoError(t, err)
	commitHash := ref.Hash()

	// Get the file changes in the commit
	fileChanges, err := GetFileChangesInCommit(repo, commitHash)
	require.NoError(t, err)

	// Verify that there is one file change and that it is for the test.txt file
	require.Len(t, fileChanges, 1)
	require.Equal(t, "test.txt", fileChanges[0].Current.Path)

	// Verify that the old Git OID is not equal to the new Git OID
	require.NotEqual(t, fileChanges[0].Previous.Digest, fileChanges[0].Current.Digest)

	//calulate the digest set for the file
	digestSet1, err := gitOIDDigestSetFromFile(filepath.Join(repoPath, "test.txt"))
	require.NoError(t, err)

	// Verify that the current digest set is equal to the calculated digest set
	require.Equal(t, digestSet1, fileChanges[0].Current.Digest)

	//make a new commit
	createTestCommit(t, repoPath, "Test commit 2")

	// Get the commit hash of the new commit
	ref, err = repo.Head()
	require.NoError(t, err)
	commitHash = ref.Hash()

	// Get the file changes in the commit
	fileChanges, err = GetFileChangesInCommit(repo, commitHash)
	require.NoError(t, err)

	// Verify that there is one file change and that it is for the test.txt file
	require.Len(t, fileChanges, 1)
	require.Equal(t, "test.txt", fileChanges[0].Current.Path)

	// Verify that the old Git OID is not equal to the new Git OID
	require.NotEqual(t, fileChanges[0].Previous.Digest, fileChanges[0].Current.Digest)

	//calulate the digest set for the file
	digestSet2, err := gitOIDDigestSetFromFile(filepath.Join(repoPath, "test.txt"))
	require.NoError(t, err)

	// Verify that the current digest set is equal to the calculated digest set
	require.Equal(t, digestSet2, fileChanges[0].Current.Digest)

	// Verify that the previous digest set is equal to the calculated digest set
	require.Equal(t, digestSet1, fileChanges[0].Previous.Digest)

	//make sure we are tracking file name changes
	err = os.Rename(filepath.Join(repoPath, "test.txt"), filepath.Join(repoPath, "test2.txt"))
	require.NoError(t, err)

	// Add the new file to the repository
	worktree, err := repo.Worktree()
	require.NoError(t, err)
	err = worktree.AddWithOptions(&git.AddOptions{
		All: true,
	})
	require.NoError(t, err)

	// Commit the changes
	_, err = worktree.Commit("Test commit 3", &git.CommitOptions{
		All: true,
		Author: &object.Signature{
			Name:  "John Doe",
			Email: "john@test.com",
			When:  time.Now(),
		},
	})
	require.NoError(t, err)

	// Get the commit hash of the new commit
	ref, err = repo.Head()
	require.NoError(t, err)

	commitHash = ref.Hash()

	// Get the file changes in the commit
	fileChanges, err = GetFileChangesInCommit(repo, commitHash)
	require.NoError(t, err)

	// Verify that the file name has changed
	require.Equal(t, "test2.txt", fileChanges[0].Current.Path)
	require.Equal(t, "test.txt", fileChanges[0].Previous.Path)

	// Verify that the old Git OID is equal to the new Git OID
	require.Equal(t, fileChanges[0].Previous.Digest, fileChanges[0].Current.Digest)

}

func TestCreateMergeCommitWithTwoParents(t *testing.T) {
	// Create a new test repository
	author := &object.Signature{
		Name:  "John Doe",
		Email: "john@testifysec.com",
		When:  time.Now(),
	}
	repo, repoPath, cleanup := createTestRepo(t)
	defer cleanup()

	//get head commit
	headCommit, err := repo.Head()
	require.NoError(t, err)

	//create a new branch
	mainBranchName := "main"
	mainBranchRef := plumbing.NewBranchReferenceName(mainBranchName)
	mainBranch := plumbing.NewHashReference(mainBranchRef, headCommit.Hash())
	err = repo.Storer.SetReference(mainBranch)
	require.NoError(t, err)

	//Branch A
	//create a test file
	_, err = createTestFile(t, repoPath, "testA.txt", "contentA")
	require.NoError(t, err)

	//calculate the digest set for the file
	digestSetA, err := gitOIDDigestSetFromFile(filepath.Join(repoPath, "testA.txt"))
	require.NoError(t, err)

	// Add the new file to the repository
	worktree, err := repo.Worktree()
	require.NoError(t, err)
	err = worktree.AddWithOptions(&git.AddOptions{
		All: true,
	})
	require.NoError(t, err)

	// Commit the changes
	commitA, err := worktree.Commit("Test commit A", &git.CommitOptions{
		All:    true,
		Author: author,
	})
	require.NoError(t, err)

	//create a new branch
	branchNameA := "branchA"
	branchRefA := plumbing.NewBranchReferenceName(branchNameA)
	branchA := plumbing.NewHashReference(branchRefA, commitA)
	err = repo.Storer.SetReference(branchA)
	require.NoError(t, err)

	//Branch B
	//create a test file
	_, err = createTestFile(t, repoPath, "testA.txt", "contentB")
	require.NoError(t, err)

	//calculate the digest set for the file
	digestSetB, err := gitOIDDigestSetFromFile(filepath.Join(repoPath, "testA.txt"))
	require.NoError(t, err)

	// Add the new file to the repository
	err = worktree.AddWithOptions(&git.AddOptions{
		All: true,
	})
	require.NoError(t, err)

	// Commit the changes
	commitB, err := worktree.Commit("Test commit B", &git.CommitOptions{
		All:    true,
		Author: author,
	})
	require.NoError(t, err)

	//create a new branch
	branchNameB := "branchB"
	branchRefB := plumbing.NewBranchReferenceName(branchNameB)
	branchB := plumbing.NewHashReference(branchRefB, commitB)
	err = repo.Storer.SetReference(branchB)
	require.NoError(t, err)

	//modify testA.txt
	_, err = createTestFile(t, repoPath, "testA.txt", "contentC")
	require.NoError(t, err)

	//calculate the digest set for the file
	digestSetC, err := gitOIDDigestSetFromFile(filepath.Join(repoPath, "testA.txt"))
	require.NoError(t, err)

	// Add the new file to the repository
	err = worktree.AddWithOptions(&git.AddOptions{
		All: true,
	})
	require.NoError(t, err)

	// Commit the changes
	commitC, err := worktree.Commit("Test commit C", &git.CommitOptions{
		All:     true,
		Parents: []plumbing.Hash{commitA, commitB},
	})
	require.NoError(t, err)

	//get the commit
	commit, err := repo.CommitObject(commitC)
	require.NoError(t, err)

	//verify that the commit has two parents
	require.Equal(t, 2, len(commit.ParentHashes))

	fileChanges, err := GetFileChangesInCommit(repo, commitC)
	require.NoError(t, err)

	//verify there are two file changes
	require.Equal(t, 2, len(fileChanges))

	//verify that the file has been modified
	require.Equal(t, "testA.txt", fileChanges[0].Current.Path)
	require.Equal(t, "testA.txt", fileChanges[0].Previous.Path)
	require.Equal(t, "testA.txt", fileChanges[1].Current.Path)
	require.Equal(t, "testA.txt", fileChanges[1].Previous.Path)

	//verify that the old Git OID is not equal to the new Git OID
	require.NotEqual(t, fileChanges[0].Previous.Digest, fileChanges[0].Current.Digest)
	require.NotEqual(t, fileChanges[1].Previous.Digest, fileChanges[1].Current.Digest)

	//verify that the old digest set is equal to digestSetA or digestSetB
	require.True(t, fileChanges[0].Previous.Digest.Equal(digestSetA) || fileChanges[0].Previous.Digest.Equal(digestSetB))
	require.True(t, fileChanges[1].Previous.Digest.Equal(digestSetA) || fileChanges[1].Previous.Digest.Equal(digestSetB))

	//verify that the new digest set is equal to digestSetC
	require.True(t, fileChanges[0].Current.Digest.Equal(digestSetC))
	require.True(t, fileChanges[1].Current.Digest.Equal(digestSetC))
}

func createTestFile(t *testing.T, repoPath string, name string, content string) (string, error) {
	filePath := filepath.Join(repoPath, name)
	file, err := os.Create(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	if _, err := file.WriteString(content); err != nil {
		return "", err
	}

	return filePath, nil
}

func gitOIDDigestSetFromFile(path string) (cryptoutil.DigestSet, error) {
	fileReader, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fileReader.Close()

	gitOidSha1, err := gitoid.New(fileReader)
	if err != nil {
		return nil, err
	}

	return cryptoutil.DigestSet{
		{
			Hash:   crypto.SHA1,
			GitOID: true,
		}: gitOidSha1.URI(),
	}, nil

}
