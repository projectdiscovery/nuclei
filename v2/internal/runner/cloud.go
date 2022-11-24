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

	if r.options.AwsBucketName != "" {
		token := strings.Join([]string{r.options.AwsAccessKey, r.options.AwsSecretKey, r.options.AwsRegion}, ":")
		if ID, err := r.processDataSourceItem(r.options.AwsBucketName, token, "s3"); err != nil {
			return nil, err
		} else {
			ids = append(ids, ID)
		}
	}
	for _, repo := range r.options.GithubTemplateRepo {
		if ID, err := r.processDataSourceItem(repo, r.options.GithubToken, "github"); err != nil {
			return nil, err
		} else {
			ids = append(ids, ID)
		}
	}
	return ids, nil
}

func (r *Runner) processDataSourceItem(repo, token, Type string) (string, error) {
	var secret string
	ID, err := r.cloudClient.StatusDataSource(nucleicloud.StatusDataSourceRequest{Repo: repo, Token: token})
	if err != nil {
		if !strings.Contains(err.Error(), "invalid status code recieved") {
			return "", errors.Wrap(err, "could not get data source status")
		}

		gologger.Info().Msgf("Adding new data source + syncing: %s\n", repo)
		ID, secret, err = r.cloudClient.AddDataSource(nucleicloud.AddDataSourceRequest{Type: Type, Repo: repo, Token: token})
		if err != nil {
			return "", errors.Wrap(err, "could not add data source")
		}
		if err = r.cloudClient.SyncDataSource(ID); err != nil {
			return "", errors.Wrap(err, "could not sync data source")
		}
		if secret != "" {
			gologger.Info().Msgf("Webhook URL for added source: %s/datasources/%s/webhook", r.options.CloudURL, ID)
			gologger.Info().Msgf("Secret for webhook: %s", secret)
		}
	}
	if r.options.UpdateTemplates {
		gologger.Info().Msgf("Syncing data source: %s (%s)\n", repo, ID)
		if err = r.cloudClient.SyncDataSource(ID); err != nil {
			return "", errors.Wrap(err, "could not sync data source")
		}
	}
	gologger.Info().Msgf("Got connected data source: %s\n", ID)
	return ID, nil
}
