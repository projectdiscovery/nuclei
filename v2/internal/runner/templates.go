package runner

import (
	"fmt"
	"os"
	"strings"

	"github.com/karrick/godirwalk"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// getParsedTemplatesFor parse the specified templates and returns a slice of the parsable ones, optionally filtered
// by severity, along with a flag indicating if workflows are present.
func (r *Runner) getParsedTemplatesFor(templatePaths []string, severities []string) (map[string]*templates.Template, int) {
	workflowCount := 0
	filterBySeverity := len(severities) > 0

	gologger.Info().Msgf("Loading templates...")

	parsedTemplates := make(map[string]*templates.Template)
	for _, match := range templatePaths {
		t, err := r.parseTemplateFile(match)
		if err != nil {
			gologger.Warning().Msgf("Could not parse file '%s': %s\n", match, err)
			continue
		}
		if len(t.Workflows) > 0 {
			workflowCount++
		}
		sev := strings.ToLower(types.ToString(t.Info["severity"]))
		if !filterBySeverity || hasMatchingSeverity(sev, severities) {
			parsedTemplates[t.ID] = t
			gologger.Info().Msgf("%s\n", r.templateLogMsg(t.ID, types.ToString(t.Info["name"]), types.ToString(t.Info["author"]), sev))
		} else {
			gologger.Error().Msgf("Excluding template %s due to severity filter (%s not in [%s])", t.ID, sev, severities)
		}
	}
	return parsedTemplates, workflowCount
}

// parseTemplateFile returns the parsed template file
func (r *Runner) parseTemplateFile(file string) (*templates.Template, error) {
	executerOpts := protocols.ExecuterOptions{
		Output:           r.output,
		Options:          r.options,
		Progress:         r.progress,
		Catalogue:        r.catalogue,
		RateLimiter:      r.ratelimiter,
		InteractshClient: r.interactsh,
		ProjectFile:      r.projectFile,
	}
	template, err := templates.Parse(file, executerOpts)
	if err != nil {
		return nil, err
	}
	return template, nil
}

func (r *Runner) templateLogMsg(id, name, author, severity string) string {
	// Display the message for the template
	message := fmt.Sprintf("[%s] %s (%s)",
		r.colorizer.BrightBlue(id).String(),
		r.colorizer.Bold(name).String(),
		r.colorizer.BrightYellow("@"+author).String())
	if severity != "" {
		message += " [" + r.severityColors.Data[severity] + "]"
	}
	return message
}

func (r *Runner) logAvailableTemplate(tplPath string) {
	t, err := r.parseTemplateFile(tplPath)
	if err != nil {
		gologger.Error().Msgf("Could not parse file '%s': %s\n", tplPath, err)
	} else {
		gologger.Print().Msgf("%s\n", r.templateLogMsg(t.ID, types.ToString(t.Info["name"]), types.ToString(t.Info["author"]), types.ToString(t.Info["severity"])))
	}
}

// ListAvailableTemplates prints available templates to stdout
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
		r.templatesConfig.CurrentVersion,
		r.templatesConfig.TemplatesDirectory,
	)
	err := directoryWalker(
		r.templatesConfig.TemplatesDirectory,
		func(path string, d *godirwalk.Dirent) error {
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

func hasMatchingSeverity(templateSeverity string, allowedSeverities []string) bool {
	for _, s := range allowedSeverities {
		s = strings.ToLower(s)
		if s != "" && strings.HasPrefix(templateSeverity, s) {
			return true
		}
	}
	return false
}

func directoryWalker(fsPath string, callback func(fsPath string, d *godirwalk.Dirent) error) error {
	err := godirwalk.Walk(fsPath, &godirwalk.Options{
		Callback: callback,
		ErrorCallback: func(fsPath string, err error) godirwalk.ErrorAction {
			return godirwalk.SkipNode
		},
		Unsorted: true,
	})

	// directory couldn't be walked
	if err != nil {
		return err
	}

	return nil
}

func isFilePath(filePath string) (bool, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return false, err
	}

	return info.Mode().IsRegular(), nil
}

func isNewPath(filePath string, pathMap map[string]bool) bool {
	if _, already := pathMap[filePath]; already {
		gologger.Warning().Msgf("Skipping already specified path '%s'", filePath)
		return false
	}
	return true
}
