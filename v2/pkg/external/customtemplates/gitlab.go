package customtemplates

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	errorutil "github.com/projectdiscovery/utils/errors"
	"github.com/xanzy/go-gitlab"
)

var _ Provider = &customTemplateGitLabRepo{}

type customTemplateGitLabRepo struct {
	gitLabClient *gitlab.Client
	serverURL    string
	projectIDs   []int
}

// NewGitLabProviders returns a new list of GitLab providers for downloading custom templates
func NewGitLabProviders(options *types.Options) ([]*customTemplateGitLabRepo, error) {
	providers := []*customTemplateGitLabRepo{}
	if options.GitLabToken != "" && !options.GitLabTemplateDisableDownload {
		// Establish a connection to GitLab and build a client object with which to download templates from GitLab
		gitLabClient, err := getGitLabClient(options.GitLabServerURL, options.GitLabToken)
		if err != nil {
			return nil, errorutil.NewWithErr(err).Msgf("Error establishing GitLab client for %s %s", options.GitLabServerURL, err)
		}

		// Create a new GitLab service client
		gitLabContainer := &customTemplateGitLabRepo{
			gitLabClient: gitLabClient,
			serverURL:    options.GitLabServerURL,
			projectIDs:   options.GitLabTemplateRepositoryIDs,
		}

		// Add the GitLab service client to the list of custom templates
		providers = append(providers, gitLabContainer)
	}
	return providers, nil
}

// Download downloads all .yaml files from a GitLab repository
func (bk *customTemplateGitLabRepo) Download(_ context.Context) {

	// Define the project and template count
	var projectCount = 0
	var templateCount = 0

	// Append the GitLab directory to the location
	location := config.DefaultConfig.CustomGitLabTemplatesDirectory

	// Ensure the CustomGitLabTemplateDirectory directory exists or create it if it doesn't yet exist
	err := os.MkdirAll(filepath.Dir(location), 0755)
	if err != nil {
		gologger.Error().Msgf("Error creating directory: %v", err)
		return
	}

	// Get the projects from the GitLab serverURL
	for _, projectID := range bk.projectIDs {

		// Get the project information from the GitLab serverURL to get the default branch and the project name
		project, _, err := bk.gitLabClient.Projects.GetProject(projectID, nil)
		if err != nil {
			gologger.Error().Msgf("error retrieving GitLab project: %s %s", project, err)
			return
		}

		// Add a subdirectory with the project ID as the subdirectory within the location
		projectOutputPath := filepath.Join(location, project.Path)

		// Ensure the subdirectory exists or create it if it doesn't yet exist
		err = os.MkdirAll(projectOutputPath, 0755)
		if err != nil {
			gologger.Error().Msgf("Error creating subdirectory: %v", err)
			return
		}

		// Get the directory listing for the files in the project
		tree, _, err := bk.gitLabClient.Repositories.ListTree(projectID, &gitlab.ListTreeOptions{
			Ref:       gitlab.String(project.DefaultBranch),
			Recursive: gitlab.Bool(true),
		})
		if err != nil {
			gologger.Error().Msgf("error retrieving files from GitLab project: %s (%d) %s", project.Name, projectID, err)
		}

		// Loop through the tree and download the files
		for _, file := range tree {
			// If the object is not a file or file extension is not .yaml, skip it
			if file.Type == "blob" && filepath.Ext(file.Path) == ".yaml" {
				gf := &gitlab.GetFileOptions{
					Ref: gitlab.String(project.DefaultBranch),
				}
				f, _, err := bk.gitLabClient.RepositoryFiles.GetFile(projectID, file.Path, gf)
				if err != nil {
					gologger.Error().Msgf("error retrieving GitLab project file: %d %s", projectID, err)
					return
				}

				// Decode the file content from base64 into bytes so that it can be written to the local filesystem
				contents, err := base64.StdEncoding.DecodeString(f.Content)
				if err != nil {
					gologger.Error().Msgf("error decoding GitLab project (%s) file: %s %s", project.Name, f.FileName, err)
					return
				}

				// Write the downloaded template to the local filesystem at the location with the filename of the blob name
				err = os.WriteFile(filepath.Join(projectOutputPath, f.FileName), contents, 0644)
				if err != nil {
					gologger.Error().Msgf("error writing GitLab project (%s) file: %s %s", project.Name, f.FileName, err)
					return
				}

				// Increment the number of templates downloaded
				templateCount++
			}
		}

		// Increment the number of projects downloaded
		projectCount++
		gologger.Info().Msgf("GitLab project '%s' (%d) cloned successfully", project.Name, projectID)
	}

	// Print the number of projects and templates downloaded
	gologger.Info().Msgf("%d templates downloaded from %d GitLab project(s) to: %s", templateCount, projectCount, location)
}

// Update is a wrapper around Download since it doesn't maintain a diff of the templates downloaded versus in the
// repository for simplicity.
func (bk *customTemplateGitLabRepo) Update(ctx context.Context) {
	if len(bk.projectIDs) == 0 {
		// No projects to download or update
		return
	}
	bk.Download(ctx)
}

// getGitLabClient returns a GitLab client for the given serverURL and token
func getGitLabClient(server string, token string) (*gitlab.Client, error) {
	client, err := gitlab.NewClient(token, gitlab.WithBaseURL(server))
	return client, err
}
