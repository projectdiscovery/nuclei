package customtemplates

import (
	"context"
	httpclient "net/http"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/google/go-github/github"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	fileutil "github.com/projectdiscovery/utils/file"
	"golang.org/x/oauth2"
	"gopkg.in/src-d/go-git.v4/plumbing/transport/http"
)

var _ Provider = &customTemplateGitHubRepo{}

type customTemplateGitHubRepo struct {
	owner       string
	reponame    string
	gitCloneURL string
	githubToken string
}

// This function download the custom github template repository
func (customTemplate *customTemplateGitHubRepo) Download(ctx context.Context) {
	clonePath := customTemplate.getLocalRepoClonePath(config.DefaultConfig.CustomGitHubTemplatesDirectory)

	if !fileutil.FolderExists(clonePath) {
		err := customTemplate.cloneRepo(clonePath, customTemplate.githubToken)
		if err != nil {
			gologger.Error().Msgf("%s", err)
		} else {
			gologger.Info().Msgf("Repo %s/%s cloned successfully at %s", customTemplate.owner, customTemplate.reponame, clonePath)
		}
		return
	}
}

func (customTemplate *customTemplateGitHubRepo) Update(ctx context.Context) {
	downloadPath := config.DefaultConfig.CustomGitHubTemplatesDirectory
	clonePath := customTemplate.getLocalRepoClonePath(downloadPath)

	// If folder does not exits then clone/download the repo
	if !fileutil.FolderExists(clonePath) {
		customTemplate.Download(ctx)
		return
	}
	err := customTemplate.pullChanges(clonePath, customTemplate.githubToken)
	if err != nil {
		gologger.Error().Msgf("%s", err)
	} else {
		gologger.Info().Msgf("Repo %s/%s successfully pulled the changes.\n", customTemplate.owner, customTemplate.reponame)
	}
}

// NewGitHubProviders returns new instance of GitHub providers for downloading custom templates
func NewGitHubProviders(options *types.Options) ([]*customTemplateGitHubRepo, error) {
	providers := []*customTemplateGitHubRepo{}
	gitHubClient := getGHClientIncognito()

	if options.GitHubTemplateDisableDownload {
		return providers, nil
	}

	for _, repoName := range options.GitHubTemplateRepo {
		owner, repo, err := getOwnerAndRepo(repoName)
		if err != nil {
			gologger.Error().Msgf("%s", err)
			continue
		}
		githubRepo, err := getGitHubRepo(gitHubClient, owner, repo, options.GitHubToken)
		if err != nil {
			gologger.Error().Msgf("%s", err)
			continue
		}
		customTemplateRepo := &customTemplateGitHubRepo{
			owner:       owner,
			reponame:    repo,
			gitCloneURL: githubRepo.GetCloneURL(),
			githubToken: options.GitHubToken,
		}
		providers = append(providers, customTemplateRepo)
	}
	return providers, nil
}

// getOwnerAndRepo returns the owner, repo, err from the given string
// e.g., it takes input projectdiscovery/nuclei-templates and
// returns owner => projectdiscovery, repo => nuclei-templates
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
func getGitHubRepo(gitHubClient *github.Client, repoOwner, repoName, githubToken string) (*github.Repository, error) {
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

// download the git repo to a given path
func (ctr *customTemplateGitHubRepo) cloneRepo(clonePath, githubToken string) error {
	r, err := git.PlainClone(clonePath, false, &git.CloneOptions{
		URL:  ctr.gitCloneURL,
		Auth: getAuth(ctr.owner, githubToken),
	})
	if err != nil {
		return errors.Errorf("%s/%s: %s", ctr.owner, ctr.reponame, err.Error())
	}
	// Add the user as well in the config. By default, user is not set
	config, _ := r.Storer.Config()
	config.User.Name = ctr.owner
	return r.SetConfig(config)
}

// performs the git pull on given repo
func (ctr *customTemplateGitHubRepo) pullChanges(repoPath, githubToken string) error {
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

// All Custom github repos are cloned in the format of 'reponame-owner' for uniqueness
func (ctr *customTemplateGitHubRepo) getLocalRepoClonePath(downloadPath string) string {
	return filepath.Join(downloadPath, ctr.reponame+"-"+ctr.owner)
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
