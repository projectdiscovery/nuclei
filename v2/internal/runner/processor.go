package runner

import (
	"fmt"
	"os"
	"path"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/remeh/sizedwaitgroup"
	"go.uber.org/atomic"
)

// processTemplateWithList process a template on the URL list
func (r *Runner) processTemplateWithList(template *templates.Template) bool {
	results := &atomic.Bool{}
	wg := sizedwaitgroup.New(r.options.BulkSize)

	r.hostMap.Scan(func(k, _ []byte) error {
		URL := string(k)
		wg.Add()
		go func(URL string) {
			defer wg.Done()

			match, err := template.Executer.Execute(URL)
			if err != nil {
				gologger.Warning().Msgf("[%s] Could not execute step: %s\n", r.colorizer.BrightBlue(template.ID), err)
			}
			results.CAS(false, match)
		}(URL)
		return nil
	})
	wg.Wait()

	return results.Load()
}

// processTemplateWithList process a template on the URL list
func (r *Runner) processWorkflowWithList(template *templates.Template) bool {
	results := &atomic.Bool{}
	wg := sizedwaitgroup.New(r.options.BulkSize)

	r.hostMap.Scan(func(k, _ []byte) error {
		URL := string(k)
		wg.Add()
		go func(URL string) {
			defer wg.Done()
			match, err := template.CompiledWorkflow.RunWorkflow(URL)
			if err != nil {
				gologger.Warning().Msgf("[%s] Could not execute step: %s\n", r.colorizer.BrightBlue(template.ID), err)
			}
			results.CAS(false, match)
		}(URL)
		return nil
	})
	wg.Wait()
	return results.Load()
}

// resolvePathWithBaseFolder resolves a path with the base folder
func resolvePathWithBaseFolder(baseFolder, templateName string) (string, error) {
	templatePath := path.Join(baseFolder, templateName)
	if _, err := os.Stat(templatePath); !os.IsNotExist(err) {
		gologger.Debug().Msgf("Found template in current directory: %s\n", templatePath)
		return templatePath, nil
	}
	return "", fmt.Errorf("no such path found: %s", templateName)
}
