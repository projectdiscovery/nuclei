package runner

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/internal/runner/nucleicloud"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
)

// Get all the scan lists for a user/apikey.
func (r *Runner) getScanList(limit int) error {
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
			res := nucleicloud.PrepareScanListOutput(v)
			if r.options.JSON {
				_ = jsoniter.NewEncoder(os.Stdout).Encode(res)
			} else {
				gologger.Silent().Msgf("%s [%d] [STATUS: %s] [MATCHED: %d] [TARGETS: %d] [TEMPLATES: %d] [DURATION: %s]\n", res.Timestamp, res.ScanID, strings.ToUpper(res.ScanStatus), res.ScanResult, res.Target, res.Template, res.ScanTime)
			}
		}
	}
	return e
}

func (r *Runner) deleteScan(id string) error {
	ID, _ := strconv.ParseInt(id, 10, 64)
	deleted, err := r.cloudClient.DeleteScan(ID)
	if !deleted.OK {
		gologger.Error().Msgf("Error in deleting the scan %s.", id)
	} else {
		gologger.Info().Msgf("Scan deleted %s.", id)
	}
	return err
}

func (r *Runner) getResults(id string, limit int) error {
	ID, _ := strconv.ParseInt(id, 10, 64)
	err := r.cloudClient.GetResults(ID, func(re *output.ResultEvent) {
		if outputErr := r.output.Write(re); outputErr != nil {
			gologger.Warning().Msgf("Could not write output: %s", outputErr)
		}
	}, false, limit)
	return err
}

func (r *Runner) getTarget(id string) error {
	ID, _ := strconv.ParseInt(id, 10, 64)
	reader, err := r.cloudClient.GetTarget(ID)
	if err != nil {
		return errors.Wrap(err, "could not get target")
	}
	defer reader.Close()

	_, _ = io.Copy(os.Stdout, reader)
	return err
}

func (r *Runner) getTemplate(id string) error {
	ID, _ := strconv.ParseInt(id, 10, 64)
	reader, err := r.cloudClient.GetTemplate(ID)
	if err != nil {
		return errors.Wrap(err, "could not get template")
	}
	defer reader.Close()

	_, _ = io.Copy(os.Stdout, reader)
	return err
}

func (r *Runner) listDatasources() error {
	datasources, err := r.cloudClient.ListDatasources()
	if err != nil {
		return err
	}
	for _, source := range datasources {
		if r.options.JSON {
			_ = jsoniter.NewEncoder(os.Stdout).Encode(source)
		} else {
			gologger.Silent().Msgf("[%s] [%d] [%s] [%s] %s", source.Updatedat.Format(nucleicloud.DDMMYYYYhhmmss), source.ID, source.Type, source.Repo, source.Path)
		}
	}
	return err
}

func (r *Runner) listTargets() error {
	items, err := r.cloudClient.ListTargets("")
	if err != nil {
		return err
	}
	for _, source := range items {
		if r.options.JSON {
			_ = jsoniter.NewEncoder(os.Stdout).Encode(source)
		} else {
			gologger.Silent().Msgf("[%d] %s (%d)", source.ID, source.Reference, source.Count)
		}
	}
	return err
}

func (r *Runner) listTemplates() error {
	items, err := r.cloudClient.ListTemplates("")
	if err != nil {
		return err
	}
	for _, source := range items {
		if r.options.JSON {
			_ = jsoniter.NewEncoder(os.Stdout).Encode(source)
		} else {
			gologger.Silent().Msgf("[%d] %s", source.ID, source.Reference)
		}
	}
	return err
}

func (r *Runner) removeDatasource(datasource string) error {
	var source string
	ID, parseErr := strconv.ParseInt(datasource, 10, 64)
	if parseErr != nil {
		source = datasource
	}

	err := r.cloudClient.RemoveDatasource(ID, source)
	if err == nil {
		gologger.Info().Msgf("Datasource deleted %s", datasource)
	}
	return err
}

func (r *Runner) addTemplate(location string) error {
	walkErr := filepath.WalkDir(location, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		base := filepath.Base(path)
		reference, templateErr := r.cloudClient.AddTemplate(base, path)
		if templateErr != nil {
			gologger.Error().Msgf("Could not upload %s: %s", path, templateErr)
		} else if reference != "" {
			gologger.Info().Msgf("Uploaded template %s: %s", base, reference)
		}
		return nil
	})
	return walkErr
}

func (r *Runner) addTarget(location string) error {
	walkErr := filepath.WalkDir(location, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".txt") {
			return nil
		}
		base := filepath.Base(location)
		reference, targetErr := r.cloudClient.AddTarget(base, location)
		if targetErr != nil {
			gologger.Error().Msgf("Could not upload %s: %s", location, targetErr)
		} else if reference != "" {
			gologger.Info().Msgf("Uploaded target %s: %s", base, reference)
		}
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
		if resp.Secret != "" {
			gologger.Info().Msgf("Webhook URL for added source: %s/datasources/%s/webhook", r.options.CloudURL, resp.Hash)
			gologger.Info().Msgf("Secret for webhook: %s", resp.Secret)
		}
	}
	if r.options.UpdateTemplates {
		gologger.Info().Msgf("Syncing data source: %s (%d)\n", repo, ID)
		if err = r.cloudClient.SyncDataSource(ID); err != nil {
			return 0, errors.Wrap(err, "could not sync data source")
		}
	}
	return ID, nil
}
