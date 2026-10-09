package installer

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	updateutils "github.com/projectdiscovery/utils/update"
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
