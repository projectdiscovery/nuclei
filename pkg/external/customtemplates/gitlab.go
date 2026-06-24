package customtemplates

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/utils/errkit"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// safeProjectOutputPath joins the GitLab project's path component to the
// custom-templates directory, ensuring the resulting path stays inside
// downloadDir even if the GitLab server returns a malicious project path.
func safeProjectOutputPath(downloadDir, projectPath string) (string, error) {
	return safeJoinWithinDirectory(downloadDir, projectPath)
}

// safeProjectFileOutputPath joins a per-file path to the per-project output
// directory, again ensuring containment. fileRelPath is preferred over the
// API-returned basename so that nested directory structure is preserved and a
// malicious server cannot collapse multiple files onto one another.
func safeProjectFileOutputPath(projectDir, fileRelPath string) (string, error) {
	return safeJoinWithinDirectory(projectDir, fileRelPath)
}

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
			errx := errkit.FromError(err)
			errx.Msgf("Error establishing GitLab client for %s %s", options.GitLabServerURL, err)
			return nil, errx
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

		// Add a subdirectory with the project path as the subdirectory within
		// the location. The project path is attacker-controllable on a
		// malicious or self-hosted GitLab server, so it must be validated for
		// containment before we MkdirAll into it.
		//
		// Use PathWithNamespace (e.g. "group/sub/repo") rather than the bare
		// repo slug Path so that two configured projects sharing a slug in
		// different namespaces land in distinct directories and cannot
		// silently overwrite each other's templates. PathWithNamespace is
		// still server-controlled, so it goes through the same containment
		// check as before.
		projectKey := project.PathWithNamespace
		if projectKey == "" {
			// Defensive fallback for older API responses where
			// PathWithNamespace might not be populated.
			projectKey = project.Path
		}
		projectOutputPath, err := safeProjectOutputPath(location, projectKey)
		if err != nil {
			gologger.Error().Msgf("Skipping unsafe GitLab project path %q: %v", projectKey, err)
			continue
		}

		// Ensure the subdirectory exists or create it if it doesn't yet exist
		err = os.MkdirAll(projectOutputPath, 0755)
		if err != nil {
			gologger.Error().Msgf("Error creating subdirectory: %v", err)
			return
		}

		// Get the directory listing for the files in the project
		tree, _, err := bk.gitLabClient.Repositories.ListTree(projectID, &gitlab.ListTreeOptions{
			Ref:       gitlab.Ptr(project.DefaultBranch),
			Recursive: gitlab.Ptr(true),
		})
		if err != nil {
			gologger.Error().Msgf("error retrieving files from GitLab project: %s (%d) %s", project.Name, projectID, err)
		}

		// Loop through the tree and download the files
		for _, file := range tree {
			// If the object is not a file or file extension is not .yaml, skip it
			if file.Type == "blob" && filepath.Ext(file.Path) == ".yaml" {
				// Resolve the destination path before reaching out to the
				// server so a malicious tree path cannot escape projectOutputPath
				// even if the server later returns a basename that points
				// elsewhere.
				outputPath, err := safeProjectFileOutputPath(projectOutputPath, file.Path)
				if err != nil {
					gologger.Error().Msgf("Skipping unsafe GitLab tree path %q: %v", file.Path, err)
					continue
				}

				gf := &gitlab.GetFileOptions{
					Ref: gitlab.Ptr(project.DefaultBranch),
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

				// Make sure the parent directory of the output file exists.
				// This preserves nested directory structure inside the project
				// (the previous implementation flattened everything by writing
				// only the basename, silently clobbering files with identical
				// names in different directories).
				if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
					gologger.Error().Msgf("error creating parent directory for GitLab project (%s) file: %s %s", project.Name, file.Path, err)
					return
				}

				// Write the downloaded template to the local filesystem at
				// the precomputed safe output path (preserves directory
				// structure and prevents traversal).
				err = os.WriteFile(outputPath, contents, 0644)
				if err != nil {
					gologger.Error().Msgf("error writing GitLab project (%s) file: %s %s", project.Name, file.Path, err)
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
