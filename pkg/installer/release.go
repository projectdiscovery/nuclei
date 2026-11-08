package installer

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/google/go-github/v92/github"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	updateutils "github.com/projectdiscovery/utils/update"
)

const (
	// TemplatesChannelStable updates nuclei-templates to the latest release.
	TemplatesChannelStable = "stable"
	// TemplatesChannelLatest updates nuclei-templates to the head of the
	// default branch, including templates merged since the latest release.
	TemplatesChannelLatest = "latest"

	templatesDefaultBranch = "main"
	shortCommitLength      = 7
)

// templateRelease is a published release of the official nuclei-templates.
type templateRelease interface {
	Version() string
	Changelog() string
	DownloadSource(showProgressBar bool, callback updateutils.AssetFileCallback) error
}

type githubTemplateRelease struct {
	*updateutils.GHReleaseDownloader
}

func (r githubTemplateRelease) Version() string   { return r.Latest.GetTagName() }
func (r githubTemplateRelease) Changelog() string { return r.Latest.GetBody() }

func (r githubTemplateRelease) DownloadSource(showProgressBar bool, callback updateutils.AssetFileCallback) error {
	return r.DownloadSourceWithCallback(showProgressBar, callback)
}

func latestGitHubTemplateRelease() (templateRelease, error) {
	downloader, err := updateutils.NewghReleaseDownloader(config.OfficialNucleiTemplatesRepoName)
	if err != nil {
		return nil, err
	}
	return githubTemplateRelease{downloader}, nil
}

// githubTemplateHead is the head commit of the official nuclei-templates
// default branch.
type githubTemplateHead struct {
	release      templateRelease // latest release, the commit is ahead of it
	commit       string
	fetchArchive templateArchiveFetcher
}

// Version returns the latest release with the short commit as semver build
// metadata (e.g. v10.3.1+3de629d). Build metadata is ignored when comparing
// versions, so it is only outdated once a newer release is published.
func (h githubTemplateHead) Version() string {
	return h.release.Version() + "+" + h.commit[:min(len(h.commit), shortCommitLength)]
}

// Changelog is empty since unreleased commits have no release notes.
func (h githubTemplateHead) Changelog() string { return "" }

// DownloadSource downloads the archive of the head commit and calls callback
// for every file in it.
func (h githubTemplateHead) DownloadSource(_ bool, callback updateutils.AssetFileCallback) error {
	archive, err := h.fetchArchive(h.commit)
	if err != nil {
		return err
	}
	return updateutils.UnpackAssetWithCallback(updateutils.Zip, archive, callback)
}

// latestGitHubTemplateHead returns the current head of the nuclei-templates
// default branch, based on the latest release.
func latestGitHubTemplateHead() (templateRelease, error) {
	release, err := latestGitHubTemplateRelease()
	if err != nil {
		return nil, err
	}

	client, err := newGitHubClient()
	if err != nil {
		return nil, err
	}
	commit, _, err := client.Repositories.GetCommitSHA1(context.Background(), updateutils.Organization, config.OfficialNucleiTemplatesRepoName, templatesDefaultBranch, "")
	if err != nil {
		return nil, fmt.Errorf("get nuclei-templates %s head: %w", templatesDefaultBranch, err)
	}

	return githubTemplateHead{release: release, commit: commit, fetchArchive: fetchTemplateArchive}, nil
}

// templateVersionRef returns the git ref of an installed templates version.
// Versions installed from the latest channel carry their commit as build
// metadata.
func templateVersionRef(version string) string {
	if _, commit, ok := strings.Cut(version, "+"); ok && commit != "" {
		return commit
	}
	return version
}

// newGitHubClient returns a GitHub client that uses GITHUB_TOKEN when set,
// like the release downloader does.
func newGitHubClient() (*github.Client, error) {
	opts := []github.ClientOptionsFunc{github.WithHTTPClient(&http.Client{Timeout: updateutils.DownloadUpdateTimeout})}
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		opts = append(opts, github.WithAuthToken(token))
	}

	client, err := github.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("create github client: %w", err)
	}
	return client, nil
}
