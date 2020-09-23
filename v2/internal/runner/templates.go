package runner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/karrick/godirwalk"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/workflows"
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
			gologger.Errorf("Could not find template file '%s': %s\n", t, err)
			continue
		}

		// Template input includes a wildcard
		if strings.Contains(absPath, "*") {
			var matches []string
			matches, err = filepath.Glob(absPath)

			if err != nil {
				gologger.Labelf("Wildcard found, but unable to glob '%s': %s\n", absPath, err)

				continue
			}

			// couldn't find templates in directory
			if len(matches) == 0 {
				gologger.Labelf("Error, no templates were found with '%s'.\n", absPath)
				continue
			} else {
				gologger.Labelf("Identified %d templates\n", len(matches))
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
				gologger.Errorf("Could not stat '%s': %s\n", absPath, err)
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
				err := directoryWalker(
					absPath,
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
					gologger.Labelf("Could not find templates in directory '%s': %s\n", absPath, err)
					continue
				}

				// couldn't find templates in directory
				if len(matches) == 0 {
					gologger.Labelf("Error, no templates were found in '%s'.\n", absPath)
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
func (r *Runner) getParsedTemplatesFor(templatePaths []string, severities string) (parsedTemplates []interface{}, workflowCount int) {
	workflowCount = 0
	severities = strings.ToLower(severities)
	allSeverities := strings.Split(severities, ",")
	filterBySeverity := len(severities) > 0

	gologger.Infof("Loading templates...")

	for _, match := range templatePaths {
		t, err := r.parseTemplateFile(match)
		switch tp := t.(type) {
		case *templates.Template:
			// only include if severity matches or no severity filtering
			sev := strings.ToLower(tp.Info.Severity)
			if !filterBySeverity || hasMatchingSeverity(sev, allSeverities) {
				parsedTemplates = append(parsedTemplates, tp)
				gologger.Infof("%s\n", r.templateLogMsg(tp.ID, tp.Info.Name, tp.Info.Author, tp.Info.Severity))
			} else {
				gologger.Warningf("Excluding template %s due to severity filter (%s not in [%s])", tp.ID, sev, severities)
			}
		case *workflows.Workflow:
			parsedTemplates = append(parsedTemplates, tp)
			gologger.Infof("%s\n", r.templateLogMsg(tp.ID, tp.Info.Name, tp.Info.Author, tp.Info.Severity))
			workflowCount++
		default:
			gologger.Errorf("Could not parse file '%s': %s\n", match, err)
		}
	}

	return parsedTemplates, workflowCount
}

func (r *Runner) parseTemplateFile(file string) (interface{}, error) {
	// check if it's a template
	template, errTemplate := templates.Parse(file)
	if errTemplate == nil {
		return template, nil
	}

	// check if it's a workflow
	workflow, errWorkflow := workflows.Parse(file)
	if errWorkflow == nil {
		return workflow, nil
	}

	if errTemplate != nil {
		return nil, errTemplate
	}

	if errWorkflow != nil {
		return nil, errWorkflow
	}

	return nil, errors.New("unknown error occurred")
}

func (r *Runner) templateLogMsg(id, name, author, severity string) string {
	// Display the message for the template
	message := fmt.Sprintf("[%s] %s (%s)",
		r.colorizer.Colorizer.BrightBlue(id).String(),
		r.colorizer.Colorizer.Bold(name).String(),
		r.colorizer.Colorizer.BrightYellow("@"+author).String())

	if severity != "" {
		message += " [" + r.colorizer.GetColorizedSeverity(severity) + "]"
	}

	return message
}

func (r *Runner) logAvailableTemplate(tplPath string) {
	t, err := r.parseTemplateFile(tplPath)
	if t != nil {
		switch tp := t.(type) {
		case *templates.Template:
			gologger.Silentf("%s\n", r.templateLogMsg(tp.ID, tp.Info.Name, tp.Info.Author, tp.Info.Severity))
		case *workflows.Workflow:
			gologger.Silentf("%s\n", r.templateLogMsg(tp.ID, tp.Info.Name, tp.Info.Author, tp.Info.Severity))
		default:
			gologger.Errorf("Could not parse file '%s': %s\n", tplPath, err)
		}
	}
}

// ListAvailableTemplates prints available templates to stdout
func (r *Runner) listAvailableTemplates() {
	if r.templatesConfig == nil {
		return
	}

	if _, err := os.Stat(r.templatesConfig.TemplatesDirectory); os.IsNotExist(err) {
		gologger.Errorf("%s does not exists", r.templatesConfig.TemplatesDirectory)
		return
	}

	gologger.Silentf(
		"\nListing available v.%s nuclei templates for %s",
		r.templatesConfig.CurrentVersion,
		r.templatesConfig.TemplatesDirectory,
	)
	err := directoryWalker(
		r.templatesConfig.TemplatesDirectory,
		func(path string, d *godirwalk.Dirent) error {
			if d.IsDir() && path != r.templatesConfig.TemplatesDirectory {
				gologger.Silentf("\n%s:\n\n", r.colorizer.Colorizer.Bold(r.colorizer.Colorizer.BgBrightBlue(d.Name())).String())
			} else if strings.HasSuffix(path, ".yaml") {
				r.logAvailableTemplate(path)
			}

			return nil
		},
	)

	// directory couldn't be walked
	if err != nil {
		gologger.Labelf("Could not find templates in directory '%s': %s\n", r.templatesConfig.TemplatesDirectory, err)
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
		gologger.Warningf("Skipping already specified path '%s'", filePath)
		return false
	}

	return true
}
