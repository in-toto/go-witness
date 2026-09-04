// Copyright 2026 The Witness Contributors
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

package githubwebhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/in-toto/go-witness/cryptoutil"
)

func TestRepositoryFromPayload(t *testing.T) {
	t.Run("missing repository", func(t *testing.T) {
		_, err := RepositoryFromPayload(map[string]any{})
		if err == nil {
			t.Fatalf("expected error for missing repository")
		}
	})

	t.Run("valid repository", func(t *testing.T) {
		payload := map[string]any{"repository": map[string]any{"name": "repo", "html_url": "https://example"}}
		r, err := RepositoryFromPayload(payload)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if r.Name != "repo" || r.HtmlUrl != "https://example" {
			t.Fatalf("unexpected repo parsed: %+v", r)
		}
	})
}

func TestSenderFromPayload(t *testing.T) {
	t.Run("missing sender", func(t *testing.T) {
		_, err := SenderFromPayload(map[string]any{})
		if err == nil {
			t.Fatalf("expected error for missing sender")
		}
	})

	t.Run("valid sender", func(t *testing.T) {
		payload := map[string]any{"sender": map[string]any{"login": "octocat"}}
		s, err := SenderFromPayload(payload)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if s.Login != "octocat" {
			t.Fatalf("unexpected sender parsed: %+v", s)
		}
	})
}

func TestPullRequestAndHeadFromPayload(t *testing.T) {
	payload := map[string]any{"pull_request": map[string]any{"html_url": "https://pr", "head": map[string]any{"sha": "deadbeef", "ref": "refs/heads/feature"}}}
	pr, err := PullRequestFromPayload(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pr.HtmlUrl != "https://pr" || pr.Head.Sha != "deadbeef" || pr.Head.Ref != "refs/heads/feature" {
		t.Fatalf("unexpected pull request parsed: %+v", pr)
	}
}

func TestCommitsAndAuthorFromPayload(t *testing.T) {
	payload := map[string]any{"commits": []any{map[string]any{"id": "c1", "author": map[string]any{"username": "alice", "email": "a@example.com"}}}}
	commits, err := CommitsFromPayload(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(commits) != 1 {
		t.Fatalf("expected 1 commit, got %d", len(commits))
	}
	c := commits[0]
	if c.Id != "c1" || c.Author.Username != "alice" || c.Author.Email != "a@example.com" {
		t.Fatalf("unexpected commit parsed: %+v", c)
	}
}

func TestValidateWebhook(t *testing.T) {
	body := []byte("{\"foo\":\"bar\"}")
	secret := []byte("s3cr3t")

	mac := hmac.New(sha256.New, secret)
	if _, err := mac.Write(body); err != nil {
		t.Fatalf("could not write to mac: %v", err)
	}
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if err := validateWebhook(body, sig, secret); err != nil {
		t.Fatalf("expected valid webhook, got error: %v", err)
	}

	if err := validateWebhook(body, "sha256=deadbeef", secret); err == nil {
		t.Fatalf("expected validation error for bad signature")
	}
}

func TestAddPushSubjects(t *testing.T) {
	payload := map[string]any{"commits": []any{map[string]any{"id": "c2", "author": map[string]any{"username": "bob", "email": "b@example.com"}}}}
	toHash := make(map[string]string)
	subjects := make(map[string]cryptoutil.DigestSet)

	if err := addPushSubjects(payload, toHash, subjects); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := toHash["commit:c2:author:username:bob"]; !ok {
		t.Fatalf("expected toHash to contain author username entry")
	}
	if _, ok := toHash["commit:c2:author:email:bob"]; !ok {
		t.Fatalf("expected toHash to contain author email entry")
	}
	if _, ok := subjects["commit:c2"]; !ok {
		t.Fatalf("expected subjects to contain commit:c2")
	}
}

func TestAddPullRequestReviewSubjects(t *testing.T) {
	payload := map[string]any{"pull_request": map[string]any{"html_url": "https://pr2", "head": map[string]any{"sha": "sha123", "ref": "refs/heads/x"}}}
	toHash := make(map[string]string)
	subjects := make(map[string]cryptoutil.DigestSet)

	if err := addPullRequestReviewSubjects(payload, toHash, subjects); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if v, ok := toHash["pullrequest:https://pr2"]; !ok || v != "https://pr2" {
		t.Fatalf("expected toHash to contain pullrequest url")
	}
	if v, ok := toHash["pullrequestheadref:refs/heads/x"]; !ok || v != "refs/heads/x" {
		t.Fatalf("expected toHash to contain pullrequest head ref")
	}
	if _, ok := subjects["pullrequestheadsha:sha123"]; !ok {
		t.Fatalf("expected subjects to contain pullrequest head sha")
	}
}
