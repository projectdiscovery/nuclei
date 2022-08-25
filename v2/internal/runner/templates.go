package runner

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/parsers"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

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

// listAvailableTemplates prints available templates to stdout
func (r *Runner) listAvailableTemplates() {
	if r.templatesConfig == nil {
		return
	}

	if _, err := os.Stat(r.templatesConfig.TemplatesDirectory); os.IsNotExist(err) {
		gologger.Error().Msgf("%s does not exists", r.templatesConfig.TemplatesDirectory)
		return
	}

	gologger.Print().Msgf(
		"\nListing available v.%s nuclei templates for %s",
		r.templatesConfig.TemplateVersion,
		r.templatesConfig.TemplatesDirectory,
	)
	err := filepath.WalkDir(
		r.templatesConfig.TemplatesDirectory,
		func(path string, d fs.DirEntry, err error) error {
			// continue on errors
			if err != nil {
				return nil
			}
			if d.IsDir() && path != r.templatesConfig.TemplatesDirectory {
				gologger.Print().Msgf("\n%s:\n\n", r.colorizer.Bold(r.colorizer.BgBrightBlue(d.Name())).String())
			} else if strings.HasSuffix(path, ".yaml") {
				r.logAvailableTemplate(path)
			}
			return nil
		},
	)
	// directory couldn't be walked
	if err != nil {
		gologger.Error().Msgf("Could not find templates in directory '%s': %s\n", r.templatesConfig.TemplatesDirectory, err)
	}
}
