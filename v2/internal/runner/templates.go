package runner

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/alecthomas/chroma/quick"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader"

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
		r.verboseTemplate(t)
	}
}

// log available templates for verbose (-vv)
func (r *Runner) verboseTemplate(tpl *templates.Template) {
	gologger.Print().Msgf("%s\n", templates.TemplateLogMessage(tpl.ID,
		types.ToString(tpl.Info.Name),
		tpl.Info.Authors.ToSlice(),
		tpl.Info.SeverityHolder.Severity))
}

func (r *Runner) listAvailableStoreTemplates(store *loader.Store) {
	gologger.Print().Msgf(
		"\nListing available v.%s nuclei templates for %s",
		r.templatesConfig.TemplateVersion,
		r.templatesConfig.TemplatesDirectory,
	)
	topLevelDir := ""
	for _, tpl := range store.Templates() {
		if hasExtraFlags(r.options) {
			path := strings.TrimPrefix(tpl.Path, r.templatesConfig.TemplatesDirectory+string(filepath.Separator))
			pathParts := strings.Split(path, string(os.PathSeparator))
			if len(pathParts) > 0 {
				if pathParts[0] != topLevelDir {
					topLevelDir = pathParts[0]
					gologger.Silent().Msgf("\n%s:\n\n", topLevelDir)
				}
			}
			if r.options.TemplateDisplay {
				highlightedTpl, err := r.highlightTemplate(tpl)
				if err != nil {
					gologger.Error().Msgf("Could not display the template %s: %s", tpl.Path, err)
					break
				}

				gologger.Silent().Msgf("File: %s\n\n%s", aurora.Cyan(tpl.Path), highlightedTpl.String())
			} else {
				gologger.Silent().Msgf(" ⬝ %s\n", strings.TrimPrefix(path, topLevelDir+string(filepath.Separator)))
			}
		} else {
			r.verboseTemplate(tpl)
		}
	}
}

func (r *Runner) highlightTemplate(tpl *templates.Template) (*bytes.Buffer, error) {
	tplContent, err := ioutil.ReadFile(tpl.Path)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	// YAML lexer, true color terminar formatter and monokai style
	err = quick.Highlight(&buf, string(tplContent), "yaml", "terminal16m", "monokai")
	if err != nil {
		return nil, err
	}

	return &buf, nil
}

func hasExtraFlags(options *types.Options) bool {
	return options.Templates != nil || options.Authors != nil ||
		options.Tags != nil || len(options.ExcludeTags) > 3 ||
		options.IncludeTags != nil || options.IncludeIds != nil ||
		options.ExcludeIds != nil || options.IncludeTemplates != nil ||
		options.ExcludedTemplates != nil || options.ExcludeMatchers != nil ||
		options.Severities != nil || options.ExcludeSeverities != nil ||
		options.Protocols != nil || options.ExcludeProtocols != nil ||
		options.IncludeConditions != nil || options.TemplateList
}
