package runner

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/internal/runner/nucleicloud"
)

// initializeCloudDataSources initializes cloud data sources
func (r *Runner) initializeCloudDataSources() ([]string, error) {
	var ids []string
	for _, repo := range r.options.GithubTemplateRepo {
		ID, err := r.cloudClient.StatusDataSource(nucleicloud.StatusDataSourceRequest{Repo: repo, Token: r.options.GithubToken})
		if err != nil {
			if !strings.Contains(err.Error(), "invalid status code recieved") {
				return nil, errors.Wrap(err, "could not get data source status")
			}

			gologger.Info().Msgf("Adding new data source + syncing: %s\n", repo)
			ID, err = r.cloudClient.AddDataSource(nucleicloud.AddDataSourceRequest{Type: "github", Repo: repo, Token: r.options.GithubToken})
			if err != nil {
				return nil, errors.Wrap(err, "could not add data source")
			}
			if err = r.cloudClient.SyncDataSource(ID); err != nil {
				return nil, errors.Wrap(err, "could not sync data source")
			}
		}
		if r.options.UpdateTemplates {
			gologger.Info().Msgf("Syncing data source: %s (%s)\n", repo, ID)
			if err = r.cloudClient.SyncDataSource(ID); err != nil {
				return nil, errors.Wrap(err, "could not sync data source")
			}
		}
		ids = append(ids, ID)
		gologger.Info().Msgf("Got connected data source: %s\n", ID)
	}
	return ids, nil
}
