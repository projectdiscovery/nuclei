package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/karrick/godirwalk"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
)

// getTemplatesFor parses the specified input template definitions and returns a list of unique, absolute template paths.
func (r *Runner) getTemplatesFor(definitions []string) []string {
	// keeps track of processed dirs and files
	processed := make(map[string]bool)
	allTemplates := []string{}

	// parses user input, handle file/directory cases and produce a list of unique templates
	for _, t := range definitions {
		var absPath string
		var err error

		if strings.Contains(t, "*") {
			dirs := strings.Split(t, "/")
			priorDir := strings.Join(dirs[:len(dirs)-1], "/")
			absPath, err = r.resolvePathIfRelative(priorDir)
			absPath += "/" + dirs[len(dirs)-1]
		} else {
			// resolve and convert relative to absolute path
			absPath, err = r.resolvePathIfRelative(t)
		}
		if err != nil {
			gologger.Error().Msgf("Could not find template file '%s': %s\n", t, err)
			continue
		}

		// Template input includes a wildcard
		if strings.Contains(absPath, "*") {
			var matches []string
			matches, err = filepath.Glob(absPath)
			if err != nil {
				gologger.Error().Msgf("Wildcard found, but unable to glob '%s': %s\n", absPath, err)
				continue
			}

			// couldn't find templates in directory
			if len(matches) == 0 {
				gologger.Error().Msgf("Error, no templates were found with '%s'.\n", absPath)
				continue
			} else {
				gologger.Verbose().Msgf("Identified %d templates\n", len(matches))
			}

			for _, match := range matches {
				if !r.checkIfInNucleiIgnore(match) {
					processed[match] = true
					allTemplates = append(allTemplates, match)
				}
			}
		} else {
			// determine file/directory
			isFile, err := isFilePath(absPath)
			if err != nil {
				gologger.Error().Msgf("Could not stat '%s': %s\n", absPath, err)
				continue
			}
			// test for uniqueness
			if !isNewPath(absPath, processed) {
				continue
			}
			// mark this absolute path as processed
			// - if it's a file, we'll never process it again
			// - if it's a dir, we'll never walk it again
			processed[absPath] = true

			if isFile {
				allTemplates = append(allTemplates, absPath)
			} else {
				matches := []string{}

				// Recursively walk down the Templates directory and run all the template file checks
				err := directoryWalker(absPath,
					func(path string, d *godirwalk.Dirent) error {
						if !d.IsDir() && strings.HasSuffix(path, ".yaml") {
							if !r.checkIfInNucleiIgnore(path) && isNewPath(path, processed) {
								matches = append(matches, path)
								processed[path] = true
							}
						}
						return nil
					},
				)
				// directory couldn't be walked
				if err != nil {
					gologger.Error().Msgf("Could not find templates in directory '%s': %s\n", absPath, err)
					continue
				}

				// couldn't find templates in directory
				if len(matches) == 0 {
					gologger.Error().Msgf("Error, no templates were found in '%s'.\n", absPath)
					continue
				}
				allTemplates = append(allTemplates, matches...)
			}
		}
	}
	return allTemplates
}

// getParsedTemplatesFor parse the specified templates and returns a slice of the parsable ones, optionally filtered
// by severity, along with a flag indicating if workflows are present.
func (r *Runner) getParsedTemplatesFor(templatePaths []string, severities string) (parsedTemplates []*templates.Template, workflowCount int) {
	workflowCount = 0
	severities = strings.ToLower(severities)
	allSeverities := strings.Split(severities, ",")
	filterBySeverity := len(severities) > 0

	gologger.Info().Msgf("Loading templates...")

	for _, match := range templatePaths {
		t, err := r.parseTemplateFile(match)
		if err != nil {
			gologger.Error().Msgf("Could not parse file '%s': %s\n", match, err)
			continue
		}
		sev := strings.ToLower(t.Info["severity"])
		if !filterBySeverity || hasMatchingSeverity(sev, allSeverities) {
			parsedTemplates = append(parsedTemplates, t)
			// Process the template like a workflow
			if t.Workflow != nil {
				workflowCount++
			}
			gologger.Info().Msgf("%s\n", r.templateLogMsg(t.ID, t.Info["name"], t.Info["author"], t.Info["severity"]))
		} else {
			gologger.Error().Msgf("Excluding template %s due to severity filter (%s not in [%s])", t.ID, sev, severities)
		}
	}
	return parsedTemplates, workflowCount
}

// parseTemplateFile returns the parsed template file
func (r *Runner) parseTemplateFile(file string) (*templates.Template, error) {
	executerOpts := &protocols.ExecuterOptions{
		Output:      r.output,
		Options:     r.options,
		Progress:    r.progress,
		RateLimiter: r.ratelimiter,
		ProjectFile: r.projectFile,
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
	}
	gologger.Print().Msgf("%s\n", r.templateLogMsg(t.ID, t.Info["name"], t.Info["author"], t.Info["severity"]))
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

func (r *Runner) resolvePathIfRelative(filePath string) (string, error) {
	if isRelative(filePath) {
		newPath, err := r.resolvePath(filePath)

		if err != nil {
			return "", err
		}
		return newPath, nil
	}

	return filePath, nil
}

func hasMatchingSeverity(templateSeverity string, allowedSeverities []string) bool {
	for _, s := range allowedSeverities {
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
