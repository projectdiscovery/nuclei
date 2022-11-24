package customtemplates

import (
	"context"
	httpclient "net/http"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/google/go-github/github"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	"golang.org/x/oauth2"
	"gopkg.in/src-d/go-git.v4/plumbing/transport/http"
)

type customTemplateGithubRepo struct {
	owner       string
	reponame    string
	gitCloneURL string
	githubToken string
}

// This function download the custom github template repository
func (customTemplate *customTemplateGithubRepo) Download(location string, ctx context.Context) {
	downloadPath := filepath.Join(location, customGithubTemplateDirectory)
	clonePath := customTemplate.getLocalRepoClonePath(downloadPath)

	if !fileutil.FolderExists(clonePath) {
		err := customTemplate.cloneRepo(clonePath, customTemplate.githubToken)
		if err != nil {
			gologger.Info().Msgf("%s", err)
		} else {
			gologger.Info().Msgf("Repo %s/%s cloned successfully at %s", customTemplate.owner, customTemplate.reponame, clonePath)
		}
		return
	}
}

func (customTemplate *customTemplateGithubRepo) Update(location string, ctx context.Context) {
	downloadPath := filepath.Join(location, customGithubTemplateDirectory)
	clonePath := customTemplate.getLocalRepoClonePath(downloadPath)

	// If folder does not exits then clone/download the repo
	if !fileutil.FolderExists(clonePath) {
		customTemplate.Download(location, ctx)
		return
	}
	err := customTemplate.pullChanges(clonePath, customTemplate.githubToken)
	if err != nil {
		gologger.Info().Msgf("%s", err)
	} else {
		gologger.Info().Msgf("Repo %s/%s successfully pulled the changes.\n", customTemplate.owner, customTemplate.reponame)
	}
}

// getOwnerAndRepo returns the owner, repo, err from the given string
// eg. it takes input projectdiscovery/nuclei-templates and
// returns owner=> projectdiscovery , repo => nuclei-templates
func getOwnerAndRepo(reponame string) (owner string, repo string, err error) {
	s := strings.Split(reponame, "/")
	if len(s) != 2 {
		err = errors.Errorf("wrong Repo name: %s", reponame)
		return
	}
	owner = s[0]
	repo = s[1]
	return
}

// returns *github.Repository if passed github repo name
func getGithubRepo(gitHubClient *github.Client, repoOwner, repoName, githubToken string) (*github.Repository, error) {
	var retried bool
getRepo:
	repo, _, err := gitHubClient.Repositories.Get(context.Background(), repoOwner, repoName)
	if err != nil {
		// retry with authentication
		if gitHubClient = getGHClientWithToken(githubToken); gitHubClient != nil && !retried {
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
func (ctr *customTemplateGithubRepo) cloneRepo(clonePath, githubToken string) error {
	r, err := git.PlainClone(clonePath, false, &git.CloneOptions{
		URL:  ctr.gitCloneURL,
		Auth: getAuth(ctr.owner, githubToken),
	})
	if err != nil {
		return errors.Errorf("%s/%s: %s", ctr.owner, ctr.reponame, err.Error())
	}
	// Add the user as well in the config. By default user is not set
	config, _ := r.Storer.Config()
	config.User.Name = ctr.owner
	return r.SetConfig(config)
}

// performs the git pull on given repo
func (ctr *customTemplateGithubRepo) pullChanges(repoPath, githubToken string) error {
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
func (ctr *customTemplateGithubRepo) getLocalRepoClonePath(downloadPath string) string {
	if fileutil.FolderExists(filepath.Join(downloadPath, ctr.reponame)) && !ctr.isRepoDirExists(filepath.Join(downloadPath, ctr.reponame)) {
		return filepath.Join(downloadPath, ctr.reponame+"-"+ctr.owner)
	}
	return filepath.Join(downloadPath, ctr.reponame)
}

// isRepoDirExists take the path and checks if the same repo or not
func (ctr *customTemplateGithubRepo) isRepoDirExists(repoPath string) bool {
	r, _ := git.PlainOpen(repoPath)
	local, _ := r.Config()
	return local.User.Name == ctr.owner // repo already cloned no need to rename and clone
}

// returns the auth object with username and github token as password
func getAuth(username, password string) *http.BasicAuth {
	if username != "" && password != "" {
		return &http.BasicAuth{Username: username, Password: password}
	}
	return nil
}

func getGHClientWithToken(token string) *github.Client {
	if token != "" {
		ctx := context.Background()
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		)
		oauthClient := oauth2.NewClient(ctx, ts)
		return github.NewClient(oauthClient)

	}
	return nil
}

func getGHClientIncognito() *github.Client {
	var tc *httpclient.Client
	return github.NewClient(tc)
}
