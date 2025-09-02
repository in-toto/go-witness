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
	"net/url"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "git"
	Type    = "https://witness.dev/attestations/git/v0.1"
	RunType = attestation.PreMaterialRunType
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor   = &Attestor{}
	_ attestation.Subjecter  = &Attestor{}
	_ attestation.BackReffer = &Attestor{}
	_ GitAttestor            = &Attestor{}
)

type GitAttestor interface {
	// Attestor
	Name() string
	Type() string
	RunType() attestation.RunType
	Attest(ctx *attestation.AttestationContext) error
	Data() *Attestor

	// Subjecter
	Subjects() map[string]cryptoutil.DigestSet

	// Backreffer
	BackRefs() map[string]cryptoutil.DigestSet
}

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type Status struct {
	Staging  string `json:"staging,omitempty" jsonschema:"title=Staging Status,description=Status of staged files in git index"`
	Worktree string `json:"worktree,omitempty" jsonschema:"title=Worktree Status,description=Status of working directory files"`
}

type Tag struct {
	Name         string `json:"name" jsonschema:"title=Tag Name,description=Name of the git tag"`
	TaggerName   string `json:"taggername" jsonschema:"title=Tagger Name,description=Name of person who created the tag"`
	TaggerEmail  string `json:"taggeremail" jsonschema:"title=Tagger Email,description=Email of person who created the tag"`
	When         string `json:"when" jsonschema:"title=Tag Date,description=When the tag was created"`
	PGPSignature string `json:"pgpsignature" jsonschema:"title=PGP Signature,description=PGP signature of the tag if signed"`
	Message      string `json:"message" jsonschema:"title=Tag Message,description=Tag annotation message"`
}

type Attestor struct {
	GitTool        string               `json:"gittool" jsonschema:"title=Git Tool,description=Git implementation used (go-git or git binary)"`
	GitBinPath     string               `json:"gitbinpath,omitempty" jsonschema:"title=Git Binary Path,description=Path to git binary if using git binary implementation"`
	GitBinHash     cryptoutil.DigestSet `json:"gitbinhash,omitempty" jsonschema:"title=Git Binary Hash,description=Hash of git binary if using git binary implementation"`
	CommitHash     string               `json:"commithash" jsonschema:"title=Commit Hash,description=SHA hash of the current HEAD commit,example=d3adb33f"`
	Author         string               `json:"author" jsonschema:"title=Author Name,description=Name of the commit author"`
	AuthorEmail    string               `json:"authoremail" jsonschema:"title=Author Email,description=Email of the commit author,format=email"`
	CommitterName  string               `json:"committername" jsonschema:"title=Committer Name,description=Name of the person who committed"`
	CommitterEmail string               `json:"committeremail" jsonschema:"title=Committer Email,description=Email of the person who committed,format=email"`
	CommitDate     string               `json:"commitdate" jsonschema:"title=Commit Date,description=Timestamp when the commit was created"`
	CommitMessage  string               `json:"commitmessage" jsonschema:"title=Commit Message,description=Full commit message"`
	Status         map[string]Status    `json:"status,omitempty" jsonschema:"title=Repository Status,description=Status of files in staging and worktree"`
	CommitDigest   cryptoutil.DigestSet `json:"commitdigest,omitempty" jsonschema:"title=Commit Digest,description=Digest of the commit object"`
	Signature      string               `json:"signature,omitempty" jsonschema:"title=Commit Signature,description=GPG signature of the commit if signed"`
	ParentHashes   []string             `json:"parenthashes,omitempty" jsonschema:"title=Parent Hashes,description=SHA hashes of parent commits"`
	TreeHash       string               `json:"treehash,omitempty" jsonschema:"title=Tree Hash,description=SHA hash of the git tree object"`
	Refs           []string             `json:"refs,omitempty" jsonschema:"title=References,description=Git references (branches and tags) pointing to this commit"`
	Remotes        []string             `json:"remotes,omitempty" jsonschema:"title=Remote URLs,description=URLs of configured git remotes"`
	Tags           []Tag                `json:"tags,omitempty" jsonschema:"title=Tags,description=Git tags associated with this commit"`
	RefNameShort   string               `json:"branch,omitempty"`
}

func New() *Attestor {
	return &Attestor{
		Status: make(map[string]Status),
	}
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
	repo, err := git.PlainOpenWithOptions(ctx.WorkingDir(), &git.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		return err
	}

	head, err := repo.Head()
	if err != nil {
		if strings.Contains(err.Error(), "reference not found") {
			return nil
		}
		return err
	}

	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return err
	}

	a.CommitDigest = cryptoutil.DigestSet{
		{
			Hash:   crypto.SHA1,
			GitOID: false,
		}: commit.Hash.String(),
	}

	remotes, err := repo.Remotes()
	if err != nil {
		return err
	}

	for _, remote := range remotes {
		for _, urlStr := range remote.Config().URLs {
			parsed, err := url.Parse(urlStr)
			if err != nil {
				// If parsing fails, fallback to the original URL
				a.Remotes = append(a.Remotes, urlStr)
				continue
			}
			// Remove any embedded user info (tokens, credentials, etc.)
			parsed.User = nil
			a.Remotes = append(a.Remotes, parsed.String())
		}
	}

	refs, err := repo.References()
	if err != nil {
		return err
	}

	// iterate over the refs and add them to the attestor
	err = refs.ForEach(func(ref *plumbing.Reference) error {
		// only add the ref if it points to the head
		if ref.Hash() != head.Hash() {
			return nil
		}

		// add the ref name to the attestor
		a.Refs = append(a.Refs, ref.Name().String())

		return nil
	})
	if err != nil {
		return err
	}

	a.CommitHash = head.Hash().String()
	a.Author = commit.Author.Name
	a.AuthorEmail = commit.Author.Email
	a.CommitterName = commit.Committer.Name
	a.CommitterEmail = commit.Committer.Email
	a.CommitDate = commit.Author.When.String()
	a.CommitMessage = commit.Message
	a.Signature = commit.PGPSignature
	a.RefNameShort = head.Name().Short()

	for _, parent := range commit.ParentHashes {
		a.ParentHashes = append(a.ParentHashes, parent.String())
	}

	tags, err := repo.TagObjects()
	if err != nil {
		return fmt.Errorf("get tags error: %s", err)
	}

	var tagList []Tag

	err = tags.ForEach(func(t *object.Tag) error {
		// check if the tag points to the head
		if t.Target.String() != head.Hash().String() {
			return nil
		}

		tagList = append(tagList, Tag{
			Name:         t.Name,
			TaggerName:   t.Tagger.Name,
			TaggerEmail:  t.Tagger.Email,
			When:         t.Tagger.When.Format(time.RFC3339),
			PGPSignature: t.PGPSignature,
			Message:      t.Message,
		})
		return nil
	})
	if err != nil {
		return fmt.Errorf("iterate tags error: %s", err)
	}
	a.Tags = tagList

	a.TreeHash = commit.TreeHash.String()

	if GitExists() {
		a.GitTool = "go-git+git-bin"

		a.GitBinPath, err = GitGetBinPath()
		if err != nil {
			return err
		}

		a.GitBinHash, err = GitGetBinHash(ctx)
		if err != nil {
			return err
		}

		a.Status, err = GitGetStatus(ctx.WorkingDir())
		if err != nil {
			return err
		}
	} else {
		a.GitTool = "go-git"

		a.Status, err = GoGitGetStatus(repo)
		if err != nil {
			return err
		}
	}

	return nil
}

func GoGitGetStatus(repo *git.Repository) (map[string]Status, error) {
	gitStatuses := make(map[string]Status)

	worktree, err := repo.Worktree()
	if err != nil {
		return map[string]Status{}, err
	}

	status, err := worktree.Status()
	if err != nil {
		return map[string]Status{}, err
	}

	for file, status := range status {
		if status.Worktree == git.Unmodified && status.Staging == git.Unmodified {
			continue
		}

		attestStatus := Status{
			Worktree: statusCodeString(status.Worktree),
			Staging:  statusCodeString(status.Staging),
		}

		gitStatuses[file] = attestStatus
	}

	return gitStatuses, nil
}

func (a *Attestor) Data() *Attestor {
	return a
}

// Documentation implements attestation.Documenter
func (a *Attestor) Documentation() attestation.Documentation {
	return attestation.Documentation{
		Summary: "Records git repository state including commit info, branches, and working directory status",
		Usage: []string{
			"Establish source code provenance for builds",
			"Detect uncommitted changes that could affect reproducibility",
			"Link artifacts to specific git commits",
		},
		Example: "witness run -s build -k key.pem -a git -- go build ./...",
	}
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	subjects := make(map[string]cryptoutil.DigestSet)
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}

	subjectName := fmt.Sprintf("commithash:%v", a.CommitHash)
	subjects[subjectName] = cryptoutil.DigestSet{
		{
			Hash:   crypto.SHA1,
			GitOID: false,
		}: a.CommitHash,
	}

	// add author email
	subjectName = fmt.Sprintf("authoremail:%v", a.AuthorEmail)
	ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(a.AuthorEmail), hashes)
	if err != nil {
		return nil
	}

	subjects[subjectName] = ds

	// add committer email
	subjectName = fmt.Sprintf("committeremail:%v", a.CommitterEmail)
	ds, err = cryptoutil.CalculateDigestSetFromBytes([]byte(a.CommitterEmail), hashes)
	if err != nil {
		return nil
	}

	subjects[subjectName] = ds

	// add parent hashes
	for _, parentHash := range a.ParentHashes {
		subjectName = fmt.Sprintf("parenthash:%v", parentHash)
		ds, err = cryptoutil.CalculateDigestSetFromBytes([]byte(parentHash), hashes)
		if err != nil {
			return nil
		}
		subjects[subjectName] = ds
	}

	// add refname short
	subjectName = fmt.Sprintf("refnameshort:%v", a.RefNameShort)
	ds, err = cryptoutil.CalculateDigestSetFromBytes([]byte(a.RefNameShort), hashes)
	if err != nil {
		return nil
	}
	subjects[subjectName] = ds

	return subjects
}

func (a *Attestor) BackRefs() map[string]cryptoutil.DigestSet {
	backrefs := make(map[string]cryptoutil.DigestSet)
	subjectName := fmt.Sprintf("commithash:%v", a.CommitHash)
	backrefs[subjectName] = cryptoutil.DigestSet{
		{
			Hash:   crypto.SHA1,
			GitOID: false,
		}: a.CommitHash,
	}
	return backrefs
}

func statusCodeString(statusCode git.StatusCode) string {
	switch statusCode {
	case git.Unmodified:
		return "unmodified"
	case git.Untracked:
		return "untracked"
	case git.Modified:
		return "modified"
	case git.Added:
		return "added"
	case git.Deleted:
		return "deleted"
	case git.Renamed:
		return "renamed"
	case git.Copied:
		return "copied"
	case git.UpdatedButUnmerged:
		return "updated"
	default:
		return string(statusCode)
	}
}
