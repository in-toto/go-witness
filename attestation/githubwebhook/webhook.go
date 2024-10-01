package githubwebhook

import (
	"fmt"
)

const (
	EventPush              = "push"
	EventPullRequest       = "pull_request"
	EventPullRequestReview = "pull_request_review"
)

// Repository contains the repository specific information found within the webhook's payload.
// Note that this is an incomplete definition of the type.
// This is contained in every webhook type that affects a repository.
type Repository struct {
	HtmlUrl string `json:"html_url"`
	Name    string `json:"name"`
}

func RepositoryFromPayload(payload map[string]any) (Repository, error) {
	repo := Repository{}
	rd, ok := payload["repository"]
	if !ok {
		return repo, fmt.Errorf("repository data not found in payload")
	}

	repoData, ok := rd.(map[string]any)
	if !ok {
		return repo, fmt.Errorf("repository data in payload was unexpected type: %T", repoData)
	}

	name, ok := repoData["name"].(string)
	if !ok {
		return repo, fmt.Errorf("repository name not in repository data")
	}

	repo.Name = name
	htmlUrl, ok := repoData["html_url"].(string)
	if !ok {
		return repo, fmt.Errorf("repository url not in repository data")
	}

	repo.HtmlUrl = htmlUrl
	return repo, nil
}

// Sender contains information about the user that triggered the webhook.
// Note that this is an incomplete definition of the type.
// This is contained in every event type.
type Sender struct {
	Login string `json:"login"`
}

func SenderFromPayload(payload map[string]any) (Sender, error) {
	sender := Sender{}
	sd, ok := payload["sender"]
	if !ok {
		return sender, fmt.Errorf("sender data not found in payload")
	}

	senderData, ok := sd.(map[string]any)
	if !ok {
		return sender, fmt.Errorf("sender data in payload was unexpected type: %T", senderData)
	}

	login, ok := senderData["login"].(string)
	if !ok {
		return sender, fmt.Errorf("sender name not in sender data")
	}

	sender.Login = login
	return sender, nil
}

// PullRequest contains information about the pull request that the webhook pertains to.
// Note that this is an incomplete definition of the type.
// This is contained in events relating to pull requests.
type PullRequest struct {
	HtmlUrl        string `json:"html_url"`
	Head           Head   `json:"head"`
	MergeCommitSha string `json:"merge_commit_sha"`
}

// Head contains information about the head commit of the pull request that the webhook pertains to.
// Note that this is an incomplete definition of the type.
// This is contained in events relating to pull requests.
type Head struct {
	Sha string `json:"sha"`
	Ref string `json:"ref"`
}

func PullRequestFromPayload(payload map[string]any) (PullRequest, error) {
	pullRequest := PullRequest{}
	sd, ok := payload["pull_request"]
	if !ok {
		return pullRequest, fmt.Errorf("pull request data not found in payload")
	}

	pullRequestData, ok := sd.(map[string]any)
	if !ok {
		return pullRequest, fmt.Errorf("pull request data in payload was unexpected type: %T", pullRequestData)
	}

	htmlUrl, ok := pullRequestData["html_url"].(string)
	if !ok {
		return pullRequest, fmt.Errorf("url not in pull request data")
	}

	pullRequest.HtmlUrl = htmlUrl

	head, err := HeadFromPullRequest(pullRequestData)
	if err != nil {
		return pullRequest, fmt.Errorf("head not in pull request data")
	}

	pullRequest.Head = head

	mergeCommitSha, ok := pullRequestData["merge_commit_sha"].(string)
	if !ok {
		return pullRequest, fmt.Errorf("merge commit sha not in pull request data")
	}

	pullRequest.MergeCommitSha = mergeCommitSha

	return pullRequest, nil
}

func HeadFromPullRequest(pullRequestData map[string]any) (Head, error) {
	head := Head{}
	hd, ok := pullRequestData["head"]
	if !ok {
		return head, fmt.Errorf("head data not found in payload")
	}

	headData, ok := hd.(map[string]any)
	if !ok {
		return head, fmt.Errorf("head data in payload was unexpected type: %T", headData)
	}

	sha, ok := headData["sha"].(string)
	if !ok {
		return head, fmt.Errorf("sha not in head data")
	}

	head.Sha = sha
	ref, ok := headData["ref"].(string)
	if !ok {
		return head, fmt.Errorf("ref not in head data")
	}

	head.Ref = ref
	return head, nil
}

// Commit contains information about a commit in a push event.
// Note that this is an incomplete definition of the type.
type Commit struct {
	Id     string `json:"id"`
	Author Author `json:"author"`
}

// Author contains information about an author of a commit.
// Note that this is an incomplete definition of the type.
type Author struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}

func CommitsFromPayload(payload map[string]any) ([]Commit, error) {
	commits := []Commit{}
	cd, ok := payload["commits"]
	if !ok {
		return nil, fmt.Errorf("commits data not in webhook payload")
	}

	commitsData, ok := cd.([]any)
	if !ok {
		return nil, fmt.Errorf("commits data was unexpected type: %T", cd)
	}

	for _, c := range commitsData {
		commitData, ok := c.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("commit data is unexpected type: %T", cd)
		}

		commit := Commit{}
		id, ok := commitData["id"].(string)
		if !ok {
			return nil, fmt.Errorf("commit id missing in webhook payload")
		}

		commit.Id = id
		author, err := AuthorFromCommitData(commitData)
		if err != nil {
			return nil, fmt.Errorf("commit author could not be parsed from payload: %v", err)
		}

		commit.Author = author
		commits = append(commits, commit)
	}

	return commits, nil
}

func AuthorFromCommitData(commitData map[string]any) (Author, error) {
	author := Author{}
	authorData, ok := commitData["author"].(map[string]any)
	if !ok {
		return author, fmt.Errorf("author not found in commit data")
	}

	email, ok := authorData["email"].(string)
	if !ok {
		return author, fmt.Errorf("author email missing in commit data")
	}

	author.Email = email
	username, ok := authorData["username"].(string)
	if !ok {
		return author, fmt.Errorf("author username missing in commit data")
	}

	author.Username = username
	return author, nil
}
