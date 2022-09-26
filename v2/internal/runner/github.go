package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"

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
	for _, repoName := range r.options.GithubTemplateRepo {
		// check if that repo exists or not
		repo, err := getRepo(repoName)
		if err != nil {
			gologger.Info().Msgf("%s\n", err.Error())
			return
		}
		clonePath := getLocalRepoClonePath(repo, downloadPath)
		// check if repo already cloned or not in the given/default path
		if r.options.UpdateTemplates == "github" && isDirectory(clonePath) {
			err = pullChanges(repo, clonePath, r.options.GithubToken)
			if err == nil {
				gologger.Info().Msgf("Repo %s successfully pulled the changes.\n", repoName)
			} else {
				gologger.Info().Msgf("Repo %s %s.\n", repoName, err)
			}
		} else {
			// only clone if repo does not exits otherwise it fails to update .git/config
			if !isDirectory(clonePath) {
				err = cloneRepo(repo, clonePath, r.options.GithubToken)
				if err == nil {
					gologger.Info().Msgf("%s successfully cloned.\n", repoName)
				}
			}
		}
	}
}

// If same repos are passed then do not download in concurrency

// performs git clone
func cloneRepo(repo *github.Repository, clonePath, githubToken string) error {
	r, err := git.PlainClone(clonePath, false, &git.CloneOptions{
		URL:      repo.GetCloneURL(),
		Progress: os.Stdout,
		Auth:     getAuth(repo.Owner.GetLogin(), githubToken),
	})
	if err != nil {
		return err
	}
	// Add the user as well in the config. By default user is not set
	config, _ := r.Storer.Config()
	config.User.Name = *repo.GetOwner().Login
	err = r.SetConfig(config)
	return err
}

// performs the git pull on given repo
func pullChanges(repo *github.Repository, repoPath, githubToken string) error {
	r, err := git.PlainOpen(repoPath)
	if err != nil {
		return err
	}
	w, err := r.Worktree()
	if err != nil {
		return err
	}
	err = w.Pull(&git.PullOptions{RemoteName: "origin", Auth: getAuth(repo.Owner.GetLogin(), githubToken)})
	if err != nil {
		return errors.Errorf("%s %s", *repo.FullName, err.Error())
	}
	return nil
}

func isRepoDirExists(repo *github.Repository, repoPath string) bool {
	r, _ := git.PlainOpen(repoPath)
	local, _ := r.Config()
	if local.User.Name == *repo.Owner.Login {
		return true // repo already cloned no need to rename and clone
	} else {
		return false
	}
}

func getLocalRepoClonePath(repo *github.Repository, downloadPath string) string {
	if isDirectory(filepath.Join(downloadPath, *repo.Name)) && !isRepoDirExists(repo, filepath.Join(downloadPath, *repo.Name)) {
		return filepath.Join(downloadPath, *repo.Name+"-"+*repo.Owner.Login)
	}
	return filepath.Join(downloadPath, *repo.Name)
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

// returns the auth object with username and github token as password
func getAuth(username, password string) *http.BasicAuth {
	if username != "" && password != "" {
		return &http.BasicAuth{Username: username, Password: password}
	}
	return nil
}

func getRepoName(reponame string) string {
	return strings.Split(reponame, "/")[1]
}

func getRepoOwner(reponame string) string {
	return strings.Split(reponame, "/")[0]
}

func isDirectory(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fileInfo.IsDir()
}
