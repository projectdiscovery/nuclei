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

type customTemplateRepo struct {
	owner       string
	reponame    string
	gitCloneURL string
}

// This function download the custom template repository
// scenario 1: -gtr custom-template.txt  flag has passed => Only download the repos. Do not update
// scenario 2: -gtr custom-template.txt -tup github   => Update the repo(git pull)  and download if any new repo
// Reason to add update and download logic in single function is scenario 2
func (r *Runner) downloadCustomTemplates(ctx context.Context) {
	downloadPath := filepath.Join(r.templatesConfig.TemplatesDirectory, "github")
	for _, customTemplate := range r.customTemplates {
		clonePath := customTemplate.getLocalRepoClonePath(downloadPath)
		if r.options.UpdateTemplates == "github" && isDirectory(clonePath) {
			err := customTemplate.pullChanges(clonePath, r.options.GithubToken)
			if err == nil {
				gologger.Info().Label("GITHUB").Msgf("Repo %s/%s successfully pulled the changes.\n", customTemplate.owner, customTemplate.reponame)
			} else {
				gologger.Error().Label("GITHUB").Msgf("%s", err)
			}
		} else {
			err := customTemplate.cloneRepo(clonePath, r.options.GithubToken)
			if err != nil {
				gologger.Error().Label("GITHUB").Msgf("%s", err)
			}
		}
	}
}

// parseCustomTemplates function reads the options.GithubTemplateRepo list,
// Checks the given repos are valid or not and stores them into runner.CustomTemplates
func (r *Runner) parseCustomTemplates() {
	for _, repoName := range r.options.GithubTemplateRepo {
		owner, repo, err := getOwnerAndRepo(repoName)
		if err != nil {
			gologger.Error().Label("GITHUB").Msgf("%s", err)
			continue
		}
		githubRepo, err := getRepo(owner, repo)
		if err != nil {
			gologger.Error().Label("GITHUB").Msgf("%s", err)
			continue
		}
		customTemplateRepo := &customTemplateRepo{
			owner:       owner,
			reponame:    repo,
			gitCloneURL: githubRepo.GetCloneURL(),
		}
		r.customTemplates = append(r.customTemplates, *customTemplateRepo)
	}
}

// getOwnerAndRepo returns the owner, repo, err from the given string
// eg. it takes input projectdiscovery/nuclei-templates and
// returns owner=> projectdiscovery , repo => nuclei-templates
func getOwnerAndRepo(reponame string) (owner string, repo string, err error) {
	s := strings.Split(reponame, "/")
	if len(s) < 2 || len(s) > 2 {
		err = errors.Errorf("wrong Repo name: %s", reponame)
	} else {
		owner = strings.Split(reponame, "/")[0]
		repo = strings.Split(reponame, "/")[1]
	}
	return
}

// returns *github.Repository if passed github repo name
func getRepo(repoOwner, repoName string) (*github.Repository, error) {
	var (
		gitHubClient *github.Client
		retried      bool
	)
	gitHubClient = getGHClientIncognito()

getRepo:
	repo, _, err := gitHubClient.Repositories.Get(context.Background(), repoOwner, repoName)
	if err != nil {
		// retry with authentication
		if gitHubClient = getGHClientWithToken(); gitHubClient != nil && !retried {
			retried = true
			goto getRepo
		}
		return nil, err
	}
	if repo == nil {
		return nil, errors.Errorf("problem getting repository: %s/%s", repoOwner, repoName)
	}
	return repo, nil
}

// download the git repo to given path
func (ctr *customTemplateRepo) cloneRepo(clonePath, githubToken string) error {
	r, err := git.PlainClone(clonePath, false, &git.CloneOptions{
		URL:      ctr.gitCloneURL,
		Progress: os.Stdout,
		Auth:     getAuth(ctr.owner, githubToken),
	})
	if err != nil {
		return errors.Errorf("%s/%s: %s", ctr.owner, ctr.reponame, err.Error())
	}
	// Add the user as well in the config. By default user is not set
	config, _ := r.Storer.Config()
	config.User.Name = ctr.owner
	err = r.SetConfig(config)
	return err
}

// performs the git pull on given repo
func (ctr *customTemplateRepo) pullChanges(repoPath, githubToken string) error {
	r, err := git.PlainOpen(repoPath)
	if err != nil {
		return err
	}
	w, err := r.Worktree()
	if err != nil {
		return err
	}
	err = w.Pull(&git.PullOptions{RemoteName: "origin", Auth: getAuth(ctr.owner, githubToken)})
	if err != nil {
		return errors.Errorf("%s/%s: %s", ctr.owner, ctr.reponame, err.Error())
	}
	return nil
}

// getLocalRepoClonePath returns the clone path.
// if same name repo directory exists from another owner then it appends the owner then and returns the path
// eg. for nuclei-templates directory exists for projectdiscovery owner, then for ehsandeep/nuclei-templates it will return nuclei-templates-ehsandeep
func (ctr *customTemplateRepo) getLocalRepoClonePath(downloadPath string) string {
	if isDirectory(filepath.Join(downloadPath, ctr.reponame)) && !ctr.isRepoDirExists(filepath.Join(downloadPath, ctr.reponame)) {
		return filepath.Join(downloadPath, ctr.reponame+"-"+ctr.owner)
	}
	return filepath.Join(downloadPath, ctr.reponame)
}

// isRepoDirExists take the path and checks if the same repo or not
func (ctr *customTemplateRepo) isRepoDirExists(repoPath string) bool {
	r, _ := git.PlainOpen(repoPath)
	local, _ := r.Config()
	if local.User.Name == ctr.owner {
		return true // repo already cloned no need to rename and clone
	} else {
		return false
	}
}

// returns the auth object with username and github token as password
func getAuth(username, password string) *http.BasicAuth {
	if username != "" && password != "" {
		return &http.BasicAuth{Username: username, Password: password}
	}
	return nil
}

// isDirectory returns true if path is directory
func isDirectory(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fileInfo.IsDir()
}
