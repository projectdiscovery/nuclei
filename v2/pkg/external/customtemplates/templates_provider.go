package customtemplates

import (
	"context"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

const (
	customGithubTemplateDirectory = "github"
	customS3TemplateDirectory     = "s3"
)

type CustomTemplateProvider interface {
	Download(location string, ctx context.Context)
	Update(location string, ctx context.Context)
}

// parseCustomTemplates function reads the options.GithubTemplateRepo list,
// Checks the given repos are valid or not and stores them into runner.CustomTemplates
func ParseCustomTemplates(options *types.Options) *[]CustomTemplateProvider {
	var customTemplates []CustomTemplateProvider
	gitHubClient := getGHClientIncognito()

	for _, repoName := range options.GithubTemplateRepo {
		owner, repo, err := getOwnerAndRepo(repoName)
		if err != nil {
			gologger.Info().Msgf("%s", err)
			continue
		}
		githubRepo, err := getGithubRepo(gitHubClient, owner, repo, options.GithubToken)
		if err != nil {
			gologger.Info().Msgf("%s", err)
			continue
		}
		customTemplateRepo := &customTemplateGithubRepo{
			owner:       owner,
			reponame:    repo,
			gitCloneURL: githubRepo.GetCloneURL(),
			githubToken: options.GithubToken,
		}
		customTemplates = append(customTemplates, customTemplateRepo)
	}
	if options.AwsBucketName != "" {
		s3c, err := getS3Client(context.TODO(), options.AwsAccessKey, options.AwsSecretKey, options.AwsRegion)
		if err != nil {
			gologger.Error().Msgf("error downloading s3 bucket %s %s", options.AwsBucketName, err)
			return &customTemplates
		}
		ctBucket := &customTemplateS3Bucket{
			bucketName: options.AwsBucketName,
			s3Client:   s3c,
		}
		if strings.Contains(options.AwsBucketName, "/") {
			bPath := strings.SplitN(options.AwsBucketName, "/", 2)
			ctBucket.bucketName = bPath[0]
			ctBucket.prefix = bPath[1]
		}
		customTemplates = append(customTemplates, ctBucket)
	}
	return &customTemplates
}
