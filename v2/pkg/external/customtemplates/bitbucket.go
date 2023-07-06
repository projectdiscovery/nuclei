package customtemplates

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/ktrysmt/go-bitbucket"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	fileutil "github.com/projectdiscovery/utils/file"
	"gopkg.in/src-d/go-git.v4/plumbing/transport/http"
)

var _ Provider = &customTemplateBitbucketRepo{}

type customTemplateBitbucketRepo struct {
	owner          string
	reponame       string
	gitCloneURL    string
	bitbucketToken string
}

// This function download the custom bitbucket template repository
func (customTemplate *customTemplateBitbucketRepo) Download(ctx context.Context) {
	clonePath := customTemplate.getLocalRepoClonePath(config.DefaultConfig.CustomBitbucketTemplatesDirectory)

	if !fileutil.FolderExists(clonePath) {
		err := customTemplate.cloneRepo(clonePath, customTemplate.bitbucketToken)
		if err != nil {
			gologger.Error().Msgf("%s", err)
		} else {
			gologger.Info().Msgf("Repo %s/%s cloned successfully at %s", customTemplate.owner, customTemplate.reponame, clonePath)
		}
		return
	}
}

func (customTemplate *customTemplateBitbucketRepo) Update(ctx context.Context) {
	downloadPath := config.DefaultConfig.CustomBitbucketTemplatesDirectory
	clonePath := customTemplate.getLocalRepoClonePath(downloadPath)

	// If folder does not exits then clone/download the repo
	if !fileutil.FolderExists(clonePath) {
		customTemplate.Download(ctx)
		return
	}
	err := customTemplate.pullChanges(clonePath, customTemplate.bitbucketToken)
	if err != nil {
		gologger.Info().Msgf("bitbucket repository %s", err)
	} else {
		gologger.Info().Msgf("Repo %s/%s successfully pulled the changes.\n", customTemplate.owner, customTemplate.reponame)
	}
}

// NewBitbucketProviders returns new instance of bitbucket providers for downloading custom templates
func NewBitbucketProviders(options *types.Options) ([]*customTemplateBitbucketRepo, error) {
	providers := []*customTemplateBitbucketRepo{}
	bitbucketClient := bitbucket.NewOAuthbearerToken(options.BitbucketToken)

	for _, repoName := range options.BitbucketTemplateRepo {
		owner, repo, err := getBitbucketOwnerAndRepo(repoName)
		if err != nil {
			gologger.Error().Msgf("%s", err)
			continue
		}
		bitbucketRepo, err := getBitbucketRepo(bitbucketClient, owner, repo, options.BitbucketToken)
		if err != nil {
			gologger.Error().Msgf("%s", err)
			continue
		}
		cloneLinks, ok := bitbucketRepo.Links["clone"]
		if !ok {
			gologger.Error().Msg("No clone links found")
			continue
		}

		cloneLinksArray, ok := cloneLinks.([]interface{})
		if !ok {
			gologger.Error().Msgf("Clone links are not an array")
			continue
		}

		// Extract clone URL from the clone links array
		var cloneURL string
		for _, linkInterface := range cloneLinksArray {
			link, ok := linkInterface.(map[string]interface{})
			if !ok {
				continue
			}
			if name, ok := link["name"].(string); ok && name == "https" {
				if href, ok := link["href"].(string); ok {
					cloneURL = href
					break
				}
			}
		}
		customTemplateRepo := &customTemplateBitbucketRepo{
			owner:          owner,
			reponame:       repo,
			gitCloneURL:    cloneURL,
			bitbucketToken: options.BitbucketToken,
		}
		providers = append(providers, customTemplateRepo)
	}
	return providers, nil
}

// getBitbucketOwnerAndRepo returns the owner, repo, err from the given string
// eg. it takes input projectdiscovery/nuclei-templates and
// returns owner=> projectdiscovery , repo => nuclei-templates
func getBitbucketOwnerAndRepo(reponame string) (owner string, repo string, err error) {
	s := strings.Split(reponame, "/")
	if len(s) != 2 {
		err = errors.Errorf("wrong Repo name: %s", reponame)
		return
	}
	owner = s[0]
	repo = s[1]
	return
}

// returns *bitbucket.Repository if passed bitbucket repo name
func getBitbucketRepo(bitbucketClient *bitbucket.Client, repoOwner, repoName, bitbucketToken string) (*bitbucket.Repository, error) {
	repo, err := bitbucketClient.Repositories.Repository.Get(&bitbucket.RepositoryOptions{
		Owner:    repoOwner,
		RepoSlug: repoName,
	})
	if err != nil {
		return nil, err
	}
	return repo, nil
}

// download the git repo to given path
func (ctr *customTemplateBitbucketRepo) cloneRepo(clonePath, bitbucketToken string) error {
	r, err := git.PlainClone(clonePath, false, &git.CloneOptions{
		URL:  ctr.gitCloneURL,
		Auth: getBitbucketAuth("x-token-auth", bitbucketToken),
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
func (ctr *customTemplateBitbucketRepo) pullChanges(repoPath, bitbucketToken string) error {
	r, err := git.PlainOpen(repoPath)
	if err != nil {
		return err
	}
	w, err := r.Worktree()
	if err != nil {
		return err
	}
	err = w.Pull(&git.PullOptions{RemoteName: "origin", Auth: getBitbucketAuth("x-token-auth", bitbucketToken)})
	if err != nil {
		return errors.Errorf("%s/%s: %s", ctr.owner, ctr.reponame, err.Error())
	}
	return nil
}

// getLocalRepoClonePath returns the clone path.
// if same name repo directory exists from another owner then it appends the owner then and returns the path
// eg. for nuclei-templates directory exists for projectdiscovery owner, then for dogancanbakir/nuclei-templates it will return nuclei-templates-dogancanbakir
func (ctr *customTemplateBitbucketRepo) getLocalRepoClonePath(downloadPath string) string {
	if fileutil.FolderExists(filepath.Join(downloadPath, ctr.reponame)) && !ctr.isRepoDirExists(filepath.Join(downloadPath, ctr.reponame)) {
		return filepath.Join(downloadPath, ctr.reponame+"-"+ctr.owner)
	}
	return filepath.Join(downloadPath, ctr.reponame)
}

// isRepoDirExists take the path and checks if the same repo or not
func (ctr *customTemplateBitbucketRepo) isRepoDirExists(repoPath string) bool {
	r, _ := git.PlainOpen(repoPath)
	local, _ := r.Config()
	return local.User.Name == ctr.owner // repo already cloned no need to rename and clone
}

// returns the auth object with username and bitbucket token as password
func getBitbucketAuth(username, password string) *http.BasicAuth {
	return &http.BasicAuth{Username: username, Password: password}
}
