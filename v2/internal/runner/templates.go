package runner

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/parsers"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// log available templates for verbose (-vv)
func (r *Runner) logAvailableTemplate(tplPath string) {
	t, err := parsers.ParseTemplate(tplPath, r.catalog)
	if err != nil {
		gologger.Error().Msgf("Could not parse file '%s': %s\n", tplPath, err)
	} else {
		gologger.Print().Msgf("%s\n", templates.TemplateLogMessage(t.ID,
			types.ToString(t.Info.Name),
			t.Info.Authors.ToSlice(),
			t.Info.SeverityHolder.Severity))
	}
}

func (r *Runner) listAvailableStoreTemplates(store *loader.Store) {
	gologger.Print().Msgf(
		"\nListing available v.%s nuclei templates for %s",
		r.templatesConfig.TemplateVersion,
		r.templatesConfig.TemplatesDirectory,
	)
	extraFlags := r.options.Templates != nil || r.options.Authors != nil ||
		r.options.Tags != nil || len(r.options.ExcludeTags) > 3 ||
		r.options.IncludeTags != nil || r.options.IncludeIds != nil ||
		r.options.ExcludeIds != nil || r.options.IncludeTemplates != nil ||
		r.options.ExcludedTemplates != nil || r.options.ExcludeMatchers != nil ||
		r.options.Severities != nil || r.options.ExcludeSeverities != nil ||
		r.options.Protocols != nil || r.options.ExcludeProtocols != nil ||
		r.options.IncludeConditions != nil || r.options.TemplateList
	for _, tl := range store.Templates() {
		if extraFlags {
			path := strings.TrimPrefix(tl.Path, r.templatesConfig.TemplatesDirectory+string(filepath.Separator))
			gologger.Silent().Msgf("%s\n", path)
		} else {
			gologger.Print().Msgf("%s\n", templates.TemplateLogMessage(tl.ID,
				types.ToString(tl.Info.Name),
				tl.Info.Authors.ToSlice(),
				tl.Info.SeverityHolder.Severity))
		}
	}
}
