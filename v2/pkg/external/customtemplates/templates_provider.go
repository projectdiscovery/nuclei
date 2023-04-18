package customtemplates

import (
	"context"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

const (
	CustomGithubTemplateDirectory = "github"
	CustomGitLabTemplateDirectory = "gitlab"
	CustomS3TemplateDirectory     = "s3"
	CustomAzureTemplateDirectory  = "azure"
)

type Provider interface {
	Download(location string, ctx context.Context)
	Update(location string, ctx context.Context)
}

// ParseCustomTemplates function reads the options.GithubTemplateRepo list,
// Checks the given repos are valid or not and stores them into runner.CustomTemplates
func ParseCustomTemplates(options *types.Options) []Provider {
	if options.Cloud {
		return nil
	}
	var customTemplates []Provider
	gitHubClient := getGHClientIncognito()

	for _, repoName := range options.GithubTemplateRepo {
		owner, repo, err := getOwnerAndRepo(repoName)
		if err != nil {
			gologger.Error().Msgf("%s", err)
			continue
		}
		githubRepo, err := getGithubRepo(gitHubClient, owner, repo, options.GithubToken)
		if err != nil {
			gologger.Error().Msgf("%s", err)
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
			return customTemplates
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
	if options.AzureContainerName != "" {
		// Establish a connection to Azure and build a client object with which to download templates from Azure Blob Storage
		azClient, err := getAzureBlobClient(options.AzureTenantID, options.AzureClientID, options.AzureClientSecret, options.AzureServiceURL)
		if err != nil {
			gologger.Error().Msgf("Error establishing Azure Blob client for %s %s", options.AzureContainerName, err)
			return customTemplates
		}

		// Create a new Azure Blob Storage container object
		azTemplateContainer := &customTemplateAzureBlob{
			azureBlobClient: azClient,
			containerName:   options.AzureContainerName,
		}

		// Add the Azure Blob Storage container object to the list of custom templates
		customTemplates = append(customTemplates, azTemplateContainer)
	}
	if options.GitLabToken != "" {
		// Establish a connection to GitLab and build a client object with which to download templates from GitLab
		gitLabClient, err := getGitLabClient(options.GitLabServerURL, options.GitLabToken)
		if err != nil {
			gologger.Error().Msgf("Error establishing GitLab client for %s %s", options.GitLabServerURL, err)
			return customTemplates
		}

		// Create a new GitLab service client
		gitLabContainer := &customTemplateGitLabRepo{
			gitLabClient: gitLabClient,
			serverURL:    options.GitLabServerURL,
			projectIDs:   options.GitLabTemplateRepositoryIDs,
		}

		// Add the GitLab service client to the list of custom templates
		customTemplates = append(customTemplates, gitLabContainer)
	}
	return customTemplates
}
