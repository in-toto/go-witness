package githubwebhook

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/log"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "githubwebhook"
	Type    = "https://witness.dev/attestations/githubwebhook/v0.1"
	RunType = attestation.PostProductRunType
)

var (
	_ attestation.Subjecter = &Attestor{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type Attestor struct {
	Payload map[string]interface{} `json:"payload"`
	Event   string                 `json:"event"`

	body        []byte
	secret      []byte
	receivedSig string
}

func New(opts ...Option) attestation.Attestor {
	a := &Attestor{}
	for _, opt := range opts {
		opt(a)
	}

	return a
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	if len(a.body) == 0 {
		return fmt.Errorf("body is required")
	}

	if len(a.secret) == 0 {
		return fmt.Errorf("secret is required")
	}

	if len(a.receivedSig) == 0 {
		return fmt.Errorf("recieved signature is required")
	}

	if err := validateWebhook(a.body, string(a.receivedSig), a.secret); err != nil {
		return fmt.Errorf("webhook validation failed: %w", err)
	}

	if err := json.Unmarshal(a.body, &a.Payload); err != nil {
		return fmt.Errorf("could not unmarshal webhook body")
	}

	return nil
}

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&a)
}

func (a *Attestor) Type() string {
	return Type
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	subjects := make(map[string]cryptoutil.DigestSet)
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	toHash := make(map[string]string)
	repo, err := RepositoryFromPayload(a.Payload)
	if err != nil {
		log.Debugf("could not parse repository data from github webhook: %v", err)
	} else {
		toHash[fmt.Sprintf("reponame:%v", repo.Name)] = repo.Name
		toHash[fmt.Sprintf("repourl:%v", repo.HtmlUrl)] = repo.HtmlUrl
	}

	sender, err := SenderFromPayload(a.Payload)
	if err != nil {
		log.Debugf("could not parse sender data from github webhook: %v", err)
	} else {
		toHash[fmt.Sprintf("sender:%v", sender.Login)] = sender.Login
	}
	switch a.Event {
	case EventPush:
		if err := addPushSubjects(a.Payload, toHash, subjects); err != nil {
			log.Debugf("could not add push event subjects: %v", err)
		}

	case EventPullRequestReview:
		if err := addPullRequestReviewSubjects(a.Payload, toHash, subjects); err != nil {
			log.Debugf("could not add pull request review subjects: %v", err)
		}

	default:
		log.Debugf("unhandled github webhook event type: %v", a.Event)
	}

	for name, val := range toHash {
		ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(val), hashes)
		if err != nil {
			log.Debugf("could not calculate digest set for subject %v: %v", name, err)
		}

		subjects[name] = ds
	}

	return subjects
}

func validateWebhook(body []byte, receivedSig string, secret []byte) error {
	receivedSigBytes, err := hex.DecodeString(strings.TrimPrefix(receivedSig, "sha256="))
	if err != nil {
		return fmt.Errorf("could not decode received signature")
	}

	mac := hmac.New(sha256.New, secret)
	if _, err := mac.Write(body); err != nil {
		return fmt.Errorf("could not calculate hmac: %v", err)
	}

	calculatedSig := mac.Sum(nil)
	if !hmac.Equal(calculatedSig, receivedSigBytes) {
		return fmt.Errorf("webhook signature did not match calculated signature")
	}

	return nil
}

func addPushSubjects(payload map[string]any, toHash map[string]string, subjects map[string]cryptoutil.DigestSet) error {
	commits, err := CommitsFromPayload(payload)
	if err != nil {
		return fmt.Errorf("could not get commits from webhook payload: %w", err)
	}

	for _, commit := range commits {
		toHash[fmt.Sprintf("commit:%v:author:username:%v", commit.Id, commit.Author.Username)] = commit.Author.Username
		toHash[fmt.Sprintf("commit:%v:author:email:%v", commit.Id, commit.Author.Username)] = commit.Author.Email
		subjects[fmt.Sprintf("commit:%v", commit.Id)] = cryptoutil.DigestSet{
			cryptoutil.DigestValue{Hash: crypto.SHA1, GitOID: false}: commit.Id,
		}
	}

	return nil
}

func addPullRequestReviewSubjects(payload map[string]any, toHash map[string]string, subjects map[string]cryptoutil.DigestSet) error {
	pullRequest, err := PullRequestFromPayload(payload)
	if err != nil {
		return fmt.Errorf("could not get pull request from webhook payload: %w", err)
	}

	toHash[fmt.Sprintf("pullrequest:%v", pullRequest.HtmlUrl)] = pullRequest.HtmlUrl
	toHash[fmt.Sprintf("pullrequestheadref:%v", pullRequest.Head.Ref)] = pullRequest.Head.Ref
	subjects[fmt.Sprintf("pullrequestheadsha:%v", pullRequest.Head.Sha)] = cryptoutil.DigestSet{
		cryptoutil.DigestValue{Hash: crypto.SHA1, GitOID: false}: pullRequest.Head.Sha,
	}

	return nil
}
