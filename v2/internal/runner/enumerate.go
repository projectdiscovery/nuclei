package runner

import (
	_ "net/http/pprof"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/internal/runner/nucleicloud"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v2/pkg/core"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"go.uber.org/atomic"
)

// runStandardEnumeration runs standard enumeration
func (r *Runner) runStandardEnumeration(executerOpts protocols.ExecuterOptions, store *loader.Store, engine *core.Engine) (*atomic.Bool, error) {
	if r.options.AutomaticScan {
		return r.executeSmartWorkflowInput(executerOpts, store, engine)
	}
	return r.executeTemplatesInput(store, engine)
}

// Get all the scan lists for a user/apikey.
func (r *Runner) getScanList() {
	client := nucleicloud.New(r.options.CloudURL, r.options.CloudAPIKey)
	items, _ := client.GetScans()
	for _, v := range items {
		gologger.Info().Msgf("Created at: %s,  Id: %s", v.CreatedAt, v.Id)
	}
}

func (r *Runner) deleteScan(id string) {
	client := nucleicloud.New(r.options.CloudURL, r.options.CloudAPIKey)
	deleted, _ := client.DeleteScan(id)
	if !deleted.OK {
		gologger.Info().Msgf("Error in deleting the scan %s.", id)
	} else {
		gologger.Info().Msgf("Scan deleted %s.", id)
	}
}

func (r *Runner) getResults(id string) {
	client := nucleicloud.New(r.options.CloudURL, r.options.CloudAPIKey)
	client.GetResults(id, func(re *output.ResultEvent) {
		if outputErr := r.output.Write(re); outputErr != nil {
			gologger.Warning().Msgf("Could not write output: %s", outputErr)
		}
	}, false)
}

// runCloudEnumeration runs cloud based enumeration
func (r *Runner) runCloudEnumeration(store *loader.Store, nostore bool) (*atomic.Bool, error) {
	now := time.Now()
	defer func() {
		gologger.Info().Msgf("Scan execution took %s", time.Since(now))
	}()
	client := nucleicloud.New(r.options.CloudURL, r.options.CloudAPIKey)

	results := &atomic.Bool{}

	targets := make([]string, 0, r.hmapInputProvider.Count())
	r.hmapInputProvider.Scan(func(value string) {
		targets = append(targets, value)
	})
	templates := make([]string, 0, len(store.Templates()))
	for _, template := range store.Templates() {
		templates = append(templates, getTemplateRelativePath(template.Path))
	}
	taskID, err := client.AddScan(&nucleicloud.AddScanRequest{
		RawTargets:      targets,
		PublicTemplates: templates,
		IsTemporary:     nostore,
	})
	if err != nil {
		return results, err
	}
	gologger.Info().Msgf("Created task with ID: %s", taskID)
	time.Sleep(3 * time.Second)

	err = client.GetResults(taskID, func(re *output.ResultEvent) {
		results.CompareAndSwap(false, true)

		if outputErr := r.output.Write(re); outputErr != nil {
			gologger.Warning().Msgf("Could not write output: %s", err)
		}
		if r.issuesClient != nil {
			if err := r.issuesClient.CreateIssue(re); err != nil {
				gologger.Warning().Msgf("Could not create issue on tracker: %s", err)
			}
		}
	}, true)
	return results, err
}

func getTemplateRelativePath(templatePath string) string {
	splitted := strings.SplitN(templatePath, "nuclei-templates", 2)
	if len(splitted) < 2 {
		return ""
	}
	return strings.TrimPrefix(splitted[1], "/")
}
