package customtemplates

import (
	"context"
	"github.com/projectdiscovery/gologger"
	"github.com/xanzy/go-gitlab"
	"os"
	"path/filepath"
	"strconv"
)

type customTemplateGitLabRepo struct {
	gitLabClient *gitlab.Client
	serverURL    string
	projectIDs   []int
}

// Download downloads all .yaml files from a GitLab repository
func (bk *customTemplateGitLabRepo) Download(location string, _ context.Context) {
	// Append the GitLab directory to the location
	location = filepath.Join(location, CustomGitLabTemplateDirectory)

	// Define the project and template count
	var projectCount = 0
	var templateCount = 0

	// Ensure the directory exists or create it if it doesn't yet exist
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
		projectOutputPath := filepath.Join(location, strconv.Itoa(projectID))

		// Ensure the subdirectory exists or create it if it doesn't yet exist
		err = os.MkdirAll(filepath.Dir(projectOutputPath), 0755)
		if err != nil {
			gologger.Error().Msgf("Error creating subdirectory: %v", err)
			return
		}

		// Get the directory listing for the files in the project
		tree, _, err := bk.gitLabClient.Repositories.ListTree(projectID, &gitlab.ListTreeOptions{
			Ref: gitlab.String(project.DefaultBranch),
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
					gologger.Error().Msgf("error retrieving GitLab project file: %s %s", projectID, err)
				}

				// Write the downloaded template to the local filesystem at the location with the filename of the blob name
				err = os.WriteFile(projectOutputPath, []byte(f.Content), 0644)
			}

			// Increment the number of templates downloaded
			templateCount++
		}

		// Increment the number of projects downloaded
		projectCount++
		gologger.Info().Msgf("GitLab project %s (%d) successfully cloned successfully", project.Name, projectID)
	}

	// Print the number of projects and templates downloaded
	gologger.Info().Msgf("%d templates downloaded from %d GitLab project(s) to: %s", templateCount, projectCount, location)
}

// Update is a wrapper around Download since it doesn't maintain a diff of the templates downloaded versus in the
// repository for simplicity.
func (bk *customTemplateGitLabRepo) Update(outputPath string, ctx context.Context) {
	bk.Download(outputPath, ctx)
}

// getGitLabClient returns a GitLab client for the given serverURL and token
func getGitLabClient(server string, token string) (*gitlab.Client, error) {
	client, err := gitlab.NewClient(token, gitlab.WithBaseURL(server))
	return client, err
}
