package automaticscan

import (
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

// getTemplateDirs returns template directories for given input
// by default it returns default template directory
func getTemplateDirs(opts Options) ([]string, error) {
	defaultTemplatesDirectories := []string{config.DefaultConfig.GetTemplateDir()}
	// adding custom template path if available
	if len(opts.ExecuterOpts.Options.Templates) > 0 {
		defaultTemplatesDirectories = append(defaultTemplatesDirectories, opts.ExecuterOpts.Options.Templates...)
	}
	// Collect path for default directories we want to look for templates in
	var allTemplates []string
	for _, directory := range defaultTemplatesDirectories {
		templates, err := opts.ExecuterOpts.Catalog.GetTemplatePath(directory)
		if err != nil {
			return nil, errors.Wrap(err, "could not get templates in directory")
		}
		allTemplates = append(allTemplates, templates...)
	}
	allTemplates = sliceutil.Dedupe(allTemplates)
	if len(allTemplates) == 0 {
		return nil, errors.New("no templates found for given input")
	}
	return allTemplates, nil
}

// LoadTemplatesWithTags loads and returns templates with given tags
func LoadTemplatesWithTags(opts Options, templateDirs []string, tags []string, logInfo bool) ([]*templates.Template, error) {
	finalTemplates := opts.Store.LoadTemplatesWithTags(templateDirs, tags)
	if len(finalTemplates) == 0 {
		return nil, errors.New("could not find any templates with tech tag")
	}

	if !opts.ExecuterOpts.Options.DisableClustering {
		// cluster and reduce requests
		totalReqBeforeCluster := getRequestCount(finalTemplates) * int(opts.Target.Count())
		finalTemplates, clusterCount := templates.ClusterTemplates(finalTemplates, opts.ExecuterOpts)
		totalReqAfterClustering := getRequestCount(finalTemplates) * int(opts.Target.Count())
		if totalReqAfterClustering < totalReqBeforeCluster && logInfo {
			gologger.Info().Msgf("Automatic scan tech-detect: Templates clustered: %d (Reduced %d Requests)", clusterCount, totalReqBeforeCluster-totalReqAfterClustering)
		}
	}

	// log template loaded if VerboseVerbose flag is set
	if opts.ExecuterOpts.Options.VerboseVerbose {
		for _, tpl := range finalTemplates {
			gologger.Print().Msgf("%s\n", templates.TemplateLogMessage(tpl.ID,
				types.ToString(tpl.Info.Name),
				tpl.Info.Authors.ToSlice(),
				tpl.Info.SeverityHolder.Severity))
		}

	}
	return finalTemplates, nil
}

// returns total requests count
func getRequestCount(templates []*templates.Template) int {
	count := 0
	for _, template := range templates {
		// ignore requests in workflows as total requests in workflow
		// depends on what templates will be called in workflow
		if len(template.Workflows) > 0 {
			continue
		}
		count += template.TotalRequests
	}
	return count
}
