package runner

import (
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/internal/runner/nucleicloud"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
)

// Get all the scan lists for a user/apikey.
func (r *Runner) getScanList(limit int) error {
	loc, _ := time.LoadLocation("Local")
	lastTime := "2099-01-02 15:04:05 +0000 UTC"

	var e error
	for {
		items, err := r.cloudClient.GetScans(limit, lastTime)
		if err != nil {
			e = err
			break
		}
		if len(items) == 0 {
			break
		}
		for _, v := range items {
			lastTime = v.CreatedAt.String()
			status := "FINISHED"
			t := v.FinishedAt
			duration := t.Sub(v.CreatedAt)
			if !v.Finished {
				status = "RUNNING"
				t = time.Now().UTC()
				duration = t.Sub(v.CreatedAt).Round(60 * time.Second)
			}
			val := v.CreatedAt.In(loc).Format(DDMMYYYYhhmmss)
			gologger.Silent().Msgf("%s [%s] [STATUS: %s] [MATCHED: %d] [TARGETS: %d] [TEMPLATES: %d] [DURATION: %s]\n", v.Id, val, status, v.Matches, v.Targets, v.Templates, duration)
		}
	}
	return e
}

func (r *Runner) deleteScan(id string) error {
	deleted, err := r.cloudClient.DeleteScan(id)
	if !deleted.OK {
		gologger.Error().Msgf("Error in deleting the scan %s.", id)
	} else {
		gologger.Info().Msgf("Scan deleted %s.", id)
	}
	return err
}

func (r *Runner) getResults(id string, limit int) error {
	err := r.cloudClient.GetResults(id, func(re *output.ResultEvent) {
		if outputErr := r.output.Write(re); outputErr != nil {
			gologger.Warning().Msgf("Could not write output: %s", outputErr)
		}
	}, false, limit)
	return err
}

func (r *Runner) listDatasources() error {
	datasources, err := r.cloudClient.ListDatasources()
	if err != nil {
		return err
	}
	for _, source := range datasources {
		gologger.Silent().Msgf("[%s] [%d] [%s] [%s] %s", source.Updatedat.Format(DDMMYYYYhhmmss), source.ID, source.Type, source.Repo, source.Path)
	}
	return err
}

func (r *Runner) listTargets() error {
	items, err := r.cloudClient.ListTargets("")
	if err != nil {
		return err
	}
	for _, source := range items {
		gologger.Silent().Msgf("%s", source.Reference)
	}
	return err
}

func (r *Runner) listTemplates() error {
	items, err := r.cloudClient.ListTemplates("")
	if err != nil {
		return err
	}
	for _, source := range items {
		gologger.Silent().Msgf("%s", source.Reference)
	}
	return err
}

func (r *Runner) removeDatasource(datasource string) error {
	ID, _ := strconv.ParseInt(datasource, 10, 64)

	err := r.cloudClient.RemoveDatasource(ID)
	if err != nil {
		gologger.Error().Msgf("Error in deleting datasource %s: %s", datasource, err)
	} else {
		gologger.Info().Msgf("Datasource deleted %s", datasource)
	}
	return err
}

func (r *Runner) addTemplate(location string) error {
	walkErr := filepath.WalkDir(location, func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		base := filepath.Base(path)
		reference, templateErr := r.cloudClient.AddTemplate(base, path)
		if templateErr != nil {
			gologger.Error().Msgf("Could not upload %s: %s", path, templateErr)
		} else {
			gologger.Info().Msgf("Uploaded template %s: %s", base, reference)
		}
		return nil
	})
	return walkErr
}

func (r *Runner) addTarget(location string) error {
	walkErr := filepath.WalkDir(location, func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() || !strings.HasSuffix(path, ".txt") {
			return nil
		}
		base := filepath.Base(location)
		reference, targetErr := r.cloudClient.AddTarget(base, location)
		if targetErr != nil {
			gologger.Error().Msgf("Could not upload %s: %s", location, targetErr)
		}
		gologger.Info().Msgf("Uploaded target %s: %s", base, reference)
		return nil
	})
	return walkErr
}

func (r *Runner) removeTarget(item string) error {
	response, err := r.cloudClient.ListTargets(item)
	if err != nil {
		return errors.Wrap(err, "could not list targets")
	}
	for _, item := range response {
		if err := r.cloudClient.RemoveTarget(item.ID); err != nil {
			gologger.Error().Msgf("Error in deleting target %s: %s", item.Reference, err)
		} else {
			gologger.Info().Msgf("Target deleted %s", item.Reference)
		}
	}
	return err
}

func (r *Runner) removeTemplate(item string) error {
	response, err := r.cloudClient.ListTemplates(item)
	if err != nil {
		return errors.Wrap(err, "could not list templates")
	}
	for _, item := range response {
		if err := r.cloudClient.RemoveTemplate(item.ID); err != nil {
			gologger.Error().Msgf("Error in deleting template %s: %s", item.Reference, err)
		} else {
			gologger.Info().Msgf("Template deleted %s", item.Reference)
		}
	}
	return err
}

// initializeCloudDataSources initializes cloud data sources
func (r *Runner) initializeCloudDataSources() error {
	if r.options.AwsBucketName != "" {
		token := strings.Join([]string{r.options.AwsAccessKey, r.options.AwsSecretKey, r.options.AwsRegion}, ":")
		if _, err := r.processDataSourceItem(r.options.AwsBucketName, token, "s3"); err != nil {
			return err
		}
	}
	for _, repo := range r.options.GithubTemplateRepo {
		if _, err := r.processDataSourceItem(repo, r.options.GithubToken, "github"); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) processDataSourceItem(repo, token, Type string) (int64, error) {
	var secret string
	ID, err := r.cloudClient.StatusDataSource(nucleicloud.StatusDataSourceRequest{Repo: repo, Token: token})
	if err != nil {
		if !strings.Contains(err.Error(), "no rows in result set") {
			return 0, errors.Wrap(err, "could not get data source status")
		}

		gologger.Info().Msgf("Adding new data source + syncing: %s\n", repo)
		resp, err := r.cloudClient.AddDataSource(nucleicloud.AddDataSourceRequest{Type: Type, Repo: repo, Token: token})
		if err != nil {
			return 0, errors.Wrap(err, "could not add data source")
		}
		ID = resp.ID
		if err = r.cloudClient.SyncDataSource(resp.ID); err != nil {
			return 0, errors.Wrap(err, "could not sync data source")
		}
		if secret != "" {
			gologger.Info().Msgf("Webhook URL for added source: %s/datasources/%s/webhook", r.options.CloudURL, resp.Hash)
			gologger.Info().Msgf("Secret for webhook: %s", secret)
		}
	}
	if r.options.UpdateTemplates {
		gologger.Info().Msgf("Syncing data source: %s (%s)\n", repo, ID)
		if err = r.cloudClient.SyncDataSource(ID); err != nil {
			return 0, errors.Wrap(err, "could not sync data source")
		}
	}
	gologger.Info().Msgf("Got connected data source: %s\n", ID)
	return ID, nil
}
