package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/go-git/go-git/v5"
	"github.com/google/go-github/github"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
	"gopkg.in/src-d/go-git.v4/plumbing/transport/http"
)

type customTemplateProvider interface {
	Download(location string, ctx context.Context)
	Update(location string, ctx context.Context)
}

type customTemplateGithubRepo struct {
	owner       string
	reponame    string
	gitCloneURL string
	githubToken string
}

type customTemplateS3Bucket struct {
	s3Client   *s3.Client
	bucketName string
	prefix     string
}

// parseCustomTemplates function reads the options.GithubTemplateRepo list,
// Checks the given repos are valid or not and stores them into runner.CustomTemplates
func (r *Runner) parseCustomTemplates() *[]customTemplateProvider {
	var customTemplates []customTemplateProvider
	gitHubClient := getGHClientIncognito()

	for _, repoName := range r.options.GithubTemplateRepo {
		owner, repo, err := getOwnerAndRepo(repoName)
		if err != nil {
			gologger.Info().Msgf("%s", err)
			continue
		}
		githubRepo, err := getGithubRepo(gitHubClient, owner, repo)
		if err != nil {
			gologger.Info().Msgf("%s", err)
			continue
		}
		customTemplateRepo := &customTemplateGithubRepo{
			owner:       owner,
			reponame:    repo,
			gitCloneURL: githubRepo.GetCloneURL(),
			githubToken: r.options.GithubToken,
		}
		customTemplates = append(customTemplates, customTemplateRepo)
	}
	if r.options.AwsBucketName != "" {
		s3c, err := getS3Client(context.TODO(), r.options.AwsAccessKey, r.options.AwsSecretKey, r.options.AwsRegion)
		if err != nil {
			gologger.Error().Msgf("error downloading s3 bucket %s %s", r.options.AwsBucketName, err)
			return &customTemplates
		}
		ctBucket := &customTemplateS3Bucket{
			bucketName: r.options.AwsBucketName,
			s3Client:   s3c,
		}
		if strings.Contains(r.options.AwsBucketName, "/") {
			bPath := strings.SplitN(r.options.AwsBucketName, "/", 2)
			ctBucket.bucketName = bPath[0]
			ctBucket.prefix = bPath[1]
		}
		customTemplates = append(customTemplates, ctBucket)
	}
	return &customTemplates
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
func getGithubRepo(gitHubClient *github.Client, repoOwner, repoName string) (*github.Repository, error) {
	var retried bool
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

// download custom templates from s3 bucket
func (bk *customTemplateS3Bucket) Download(location string, ctx context.Context) {
	downloadPath := filepath.Join(location, customS3TemplateDirectory, bk.bucketName)

	manager := manager.NewDownloader(bk.s3Client)
	paginator := s3.NewListObjectsV2Paginator(bk.s3Client, &s3.ListObjectsV2Input{
		Bucket: &bk.bucketName,
		Prefix: &bk.prefix,
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			gologger.Error().Msgf("error downloading s3 bucket %s %s", bk.bucketName, err)
			return
		}
		for _, obj := range page.Contents {
			if err := downloadToFile(manager, downloadPath, bk.bucketName, aws.ToString(obj.Key)); err != nil {
				gologger.Error().Msgf("error downloading s3 bucket %s %s", bk.bucketName, err)
				return
			}
		}
	}
	gologger.Info().Msgf("AWS bucket %s successfully cloned successfully at %s", bk.bucketName, downloadPath)
}

// download custom templates from s3 bucket
func (bk *customTemplateS3Bucket) Update(location string, ctx context.Context) {
	bk.Download(location, ctx)
}

func downloadToFile(downloader *manager.Downloader, targetDirectory, bucket, key string) error {
	// Create the directories in the path
	file := filepath.Join(targetDirectory, key)
	if err := os.MkdirAll(filepath.Dir(file), 0775); err != nil {
		return err
	}

	// Set up the local file
	fd, err := os.Create(file)
	if err != nil {
		return err
	}
	defer fd.Close()

	// Download the file using the AWS SDK for Go
	_, err = downloader.Download(context.TODO(), fd, &s3.GetObjectInput{Bucket: &bucket, Key: &key})

	return err
}

func getS3Client(ctx context.Context, acccessKey, secretKey, region string) (*s3.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(acccessKey, secretKey, "")), config.WithRegion(region))
	if err != nil {
		return nil, err
	}
	return s3.NewFromConfig(cfg), nil
}
