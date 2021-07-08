package runner

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/karrick/godirwalk"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"gopkg.in/yaml.v2"
)

// parseTemplateFile returns the parsed template file
func (r *Runner) parseTemplateFile(file string) (*templates.Template, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	template := &templates.Template{}
	err = yaml.NewDecoder(bytes.NewReader(data)).Decode(template)
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
		r.colorizer.BrightYellow(appendAtSignToAuthors(author)).String())
	if severity != "" {
		message += " [" + r.severityColors.Data[severity] + "]"
	}
	return message
}

// appendAtSignToAuthors appends @ before each author and returns final string
func appendAtSignToAuthors(author string) string {
	authors := strings.Split(author, ",")
	if len(authors) == 0 {
		return "@none"
	}
	if len(authors) == 1 {
		if !strings.HasPrefix(authors[0], "@") {
			return fmt.Sprintf("@%s", authors[0])
		}
		return authors[0]
	}
	values := make([]string, 0, len(authors))
	for _, k := range authors {
		if !strings.HasPrefix(authors[0], "@") {
			values = append(values, fmt.Sprintf("@%s", k))
		} else {
			values = append(values, k)
		}
	}
	return strings.Join(values, ",")
}

func (r *Runner) logAvailableTemplate(tplPath string) {
	t, err := r.parseTemplateFile(tplPath)
	if err != nil {
		gologger.Error().Msgf("Could not parse file '%s': %s\n", tplPath, err)
	} else {
		gologger.Info().Msgf("%s\n", r.templateLogMsg(t.ID, types.ToString(t.Info["name"]), types.ToString(t.Info["author"]), types.ToString(t.Info["severity"])))
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

func directoryWalker(fsPath string, callback func(fsPath string, d *godirwalk.Dirent) error) error {
	return godirwalk.Walk(fsPath, &godirwalk.Options{
		Callback: callback,
		ErrorCallback: func(fsPath string, err error) godirwalk.ErrorAction {
			return godirwalk.SkipNode
		},
		Unsorted: true,
	})
}
