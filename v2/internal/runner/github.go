package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/go-git/go-git/v5"
	"github.com/google/go-github/github"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"gopkg.in/src-d/go-git.v4/plumbing/transport/http"
)

// This function download the custom template repositories in given location
// scenario 1: -gtr custom-template.txt  flag has passed => Only download the repos. Do not update
// scenario 2: -gtr custom-template.txt -tup github   => Update the repo(git pull)  and download if any new repo
// Reason to add update and download logic in single function is scenario 2
func (r *Runner) downloadCustomTemplates(downloadPath string, ctx context.Context) {
	var wg sync.WaitGroup
	for _, repoName := range r.options.GithubTemplateRepo {
		wg.Add(1)
		go func(repoName string) {
			defer wg.Done()
			// check if that repo exists or not
			repo, err := getRepo(repoName)
			if err != nil {
				gologger.Info().Msgf("%s\n", err.Error())
				return
			}
			// check if repo already cloned or not in the given/default path
			if r.options.UpdateTemplates == "github" && isAlreadyExists(downloadPath, repoName) {
				err = pullChanges(repo, filepath.Join(downloadPath, *repo.Name))
				if err == nil {
					gologger.Info().Msgf("Repo %s successfully pulled the changes.\n", repoName)
				}
			} else {
				err = cloneRepo(repo, filepath.Join(downloadPath, *repo.Name))
				if err == nil {
					gologger.Info().Msgf("%s successfully cloned.\n", repoName)
				}
			}
			if err != nil {
				gologger.Info().Msgf("%s %s", repoName, err.Error())
			}
		}(repoName)
	}
	wg.Wait()
}

// performs git clone
func cloneRepo(repo *github.Repository, clonePath string) error {
	_, err := git.PlainClone(clonePath, false, &git.CloneOptions{
		URL:      repo.GetCloneURL(),
		Progress: os.Stdout,
		Auth:     getAuth(repo.Owner.GetLogin(), getGithubToken()),
	})
	if err != nil {
		return err
	}
	return nil
}

// performs the git pull on given repo
func pullChanges(repo *github.Repository, repoPath string) error {
	r, err := git.PlainOpen(repoPath)
	if err != nil {
		return err
	}
	w, err := r.Worktree()
	if err != nil {
		return err
	}

	err = w.Pull(&git.PullOptions{RemoteName: "origin", Auth: getAuth(repo.Owner.GetLogin(), getGithubToken())})
	if err != nil {
		return errors.Errorf("%s %s", *repo.FullName, err.Error())
	}
	return nil
}

// returns *github.Repository if passed github repo name
func getRepo(repoPath string) (*github.Repository, error) {
	var (
		gitHubClient *github.Client
		retried      bool
	)
	gitHubClient = getGHClientIncognito()

getRepo:
	repo, _, err := gitHubClient.Repositories.Get(context.Background(), getRepoOwner(repoPath), getRepoName(repoPath))
	if err != nil {
		// retry with authentication
		if gitHubClient = getGHClientWithToken(); gitHubClient != nil && !retried {
			retried = true
			goto getRepo
		}
		return nil, err
	}

	if repo == nil {
		return nil, errors.New("problem getting repository")
	}

	return repo, nil
}

// returns true if repo already cloned
func isAlreadyExists(diskpath, repo string) bool {
	repoName := getRepoName(repo)
	customTemplateRepoPath := filepath.Join(diskpath, repoName)
	if _, statErr := os.Stat(customTemplateRepoPath); !os.IsNotExist(statErr) {
		return true
	}
	return false
}

// returns the auth object with username and github token as password
func getAuth(username, password string) *http.BasicAuth {
	if username != "" && password != "" {
		return &http.BasicAuth{Username: username, Password: password}
	}
	return nil
}

// returns the github token
func getGithubToken() string {
	if token, ok := os.LookupEnv("GITHUB_TOKEN"); ok {
		return token
	}
	return ""
}

func getRepoName(reponame string) string {
	return strings.Split(reponame, "/")[1]
}

func getRepoOwner(reponame string) string {
	return strings.Split(reponame, "/")[0]
}
