package runner

import (
	"bytes"
	"path/filepath"
	"sort"
	"strings"

	"github.com/alecthomas/chroma/quick"
	jsoniter "github.com/json-iterator/go"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// log available templates for verbose (-vv)
func (r *Runner) logAvailableTemplate(tplPath string) {
	t, err := r.parser.ParseTemplate(tplPath, r.catalog)
	tpl, ok := t.(*templates.Template)
	if !ok {
		panic("not a template")
	}
	if err != nil {
		gologger.Error().Msgf("Could not parse file '%s': %s\n", tplPath, err)
	} else {
		r.verboseTemplate(tpl)
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
		"\nListing available %v nuclei templates for %v",
		config.DefaultConfig.TemplateVersion,
		config.DefaultConfig.TemplatesDirectory,
	)
	for _, tpl := range store.Templates() {
		if hasExtraFlags(r.options) {
			if r.options.TemplateDisplay {
				colorize := !r.options.NoColor
				path := tpl.Path
				tplBody, err := store.ReadTemplateFromURI(path, true)
				if err != nil {
					gologger.Error().Msgf("Could not read the template %s: %s", path, err)
					continue
				}
				if colorize {
					path = aurora.Cyan(tpl.Path).String()
					tplBody, err = r.highlightTemplate(&tplBody)
					if err != nil {
						gologger.Error().Msgf("Could not highlight the template %s: %s", tpl.Path, err)
						continue
					}
				}
				gologger.Silent().Msgf("Template: %s\n\n%s", path, tplBody)
			} else {
				gologger.Silent().Msgf("%s\n", strings.TrimPrefix(tpl.Path, config.DefaultConfig.TemplatesDirectory+string(filepath.Separator)))
			}
		} else {
			r.verboseTemplate(tpl)
		}
	}
}

func (r *Runner) listAvailableStoreTags(store *loader.Store) {
	gologger.Print().Msgf(
		"\nListing available %v nuclei tags for %v",
		config.DefaultConfig.TemplateVersion,
		config.DefaultConfig.TemplatesDirectory,
	)
	tagsMap := make(map[string]int)
	for _, tpl := range store.Templates() {
		for _, tag := range tpl.Info.Tags.ToSlice() {
			tagsMap[tag]++
		}
	}
	type kv struct {
		Key   string `json:"tag"`
		Value int    `json:"count"`
	}
	var tagsList []kv
	for k, v := range tagsMap {
		tagsList = append(tagsList, kv{k, v})
	}
	sort.Slice(tagsList, func(i, j int) bool {
		return tagsList[i].Value > tagsList[j].Value
	})

	for _, tag := range tagsList {
		if r.options.JSONL {
			marshalled, _ := jsoniter.Marshal(tag)
			gologger.Silent().Msgf("%s\n", string(marshalled))
		} else {
			gologger.Silent().Msgf("%s (%d)\n", tag.Key, tag.Value)
		}
	}
}

func (r *Runner) highlightTemplate(body *[]byte) ([]byte, error) {
	var buf bytes.Buffer
	// YAML lexer, true color terminal formatter and monokai style
	err := quick.Highlight(&buf, string(*body), "yaml", "terminal16m", "monokai")
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
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
