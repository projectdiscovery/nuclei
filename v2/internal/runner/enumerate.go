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
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"go.uber.org/atomic"
)

// runStandardEnumeration runs standard enumeration
func (r *Runner) runStandardEnumeration(executerOpts protocols.ExecuterOptions, store *loader.Store, engine *core.Engine) (*atomic.Bool, error) {
	if r.options.AutomaticScan {
		return r.executeSmartWorkflowInput(executerOpts, store, engine)
	}
	return r.executeTemplatesInput(store, engine)
}

// runCloudEnumeration runs cloud based enumeration
func (r *Runner) runCloudEnumeration(store *loader.Store) (*atomic.Bool, error) {
	now := time.Now()
	defer func() {
		gologger.Info().Msgf("Scan execution took %s", time.Since(now))
	}()
	client := nucleicloud.New(r.options.CloudURL, r.options.CloudAPIKey)

	results := &atomic.Bool{}

	targets := make([]*contextargs.MetaInput, 0, r.hmapInputProvider.Count())
	r.hmapInputProvider.Scan(func(value *contextargs.MetaInput) bool {
		targets = append(targets, value)
		return true
	})
	templates := make([]string, 0, len(store.Templates()))
	for _, template := range store.Templates() {
		templates = append(templates, getTemplateRelativePath(template.Path))
	}
	taskID, err := client.AddScan(&nucleicloud.AddScanRequest{
		RawTargets:      targets,
		PublicTemplates: templates,
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
	})
	return results, err
}

func getTemplateRelativePath(templatePath string) string {
	splitted := strings.SplitN(templatePath, "nuclei-templates", 2)
	if len(splitted) < 2 {
		return ""
	}
	return strings.TrimPrefix(splitted[1], "/")
}
