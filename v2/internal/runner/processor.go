package runner

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/kb"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/kb/references"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/remeh/sizedwaitgroup"
	"go.uber.org/atomic"
)

// processTemplateWithList execute a template against the list of user provided targets
func (r *Runner) processTemplateWithList(template *templates.Template) bool {
	results := &atomic.Bool{}
	wg := sizedwaitgroup.New(r.options.BulkSize)
	r.hostMap.Scan(func(k, _ []byte) error {
		URL := string(k)

		// Skip if the host has had errors
		if r.hostErrors != nil && r.hostErrors.Check(URL) {
			return nil
		}
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

// processTemplateWithListAndDeps execute a template against the list of user provided targets
// with a list of dependencies as well.
func (r *Runner) processTemplateWithListAndDeps(template *templates.Template, references *references.ReferenceAnalysis, deps []references.ValueDependency, templatesMap map[string]*templates.Template) bool {
	results := &atomic.Bool{}
	wg := sizedwaitgroup.New(r.options.BulkSize)

	depsMap := make(map[string]struct{})
	for _, value := range deps {
		depsMap[value.FullReference] = struct{}{}
	}
	r.hostMap.Scan(func(k, _ []byte) error {
		URL := string(k)

		// Skip if the host has had errors
		if r.hostErrors != nil && r.hostErrors.Check(URL) {
			return nil
		}

		wg.Add()
		go func(URL string) {
			defer wg.Done()

			r.executeDependenciesRecursive(URL, template, deps, results, references, templatesMap, depsMap)
		}(URL)
		return nil
	})
	wg.Wait()

	// Delete all the dependencies for the template.
	for value := range depsMap {
		kb.Global.Delete(value)
	}
	return results.Load()
}

func (r *Runner) executeDependenciesRecursive(URL string, template *templates.Template, deps []references.ValueDependency, results *atomic.Bool, references *references.ReferenceAnalysis, templatesMap map[string]*templates.Template, depsMap map[string]struct{}) {
	var foundValues bool
	resultCallback := func(result *output.InternalWrappedEvent) {
		if result.OperatorsResult != nil {
			matched := template.Executer.WriteOutput(result)
			results.CAS(false, matched)

			for _, dependency := range deps {
				if data, ok := result.OperatorsResult.DynamicValues[dependency.Value]; ok {
					foundValues = true
					kb.Global.Set(URL, dependency.FullReference, types.ToString(data))
				}
			}
		}
	}

	dynamicValues := map[string]interface{}{"Input": URL}
	err := template.Executer.ExecuteWithResults(URL, dynamicValues, resultCallback)
	if err != nil {
		gologger.Warning().Msgf("[%s] Could not execute step: %s\n", r.colorizer.BrightBlue(template.ID), err)
	}
	if !foundValues {
		return
	}

	for _, value := range deps {
		if depTemplate, ok := templatesMap[value.Path]; ok {
			depTemplateDeps := references.Dependencies[depTemplate.ID]

			// Add all unique new deps to the deps map for tracking and later deletion
			for _, value := range depTemplateDeps {
				if _, depsOk := depsMap[value.FullReference]; !depsOk {
					depsMap[value.FullReference] = struct{}{}
				}
			}
			r.executeDependenciesRecursive(URL, depTemplate, depTemplateDeps, results, references, templatesMap, depsMap)
		}
	}
}

// processTemplateWithList process a template on the URL list
func (r *Runner) processWorkflowWithList(template *templates.Template) bool {
	results := &atomic.Bool{}
	wg := sizedwaitgroup.New(r.options.BulkSize)

	r.hostMap.Scan(func(k, _ []byte) error {
		URL := string(k)

		// Skip if the host has had errors
		if r.hostErrors != nil && r.hostErrors.Check(URL) {
			return nil
		}
		wg.Add()
		go func(URL string) {
			defer wg.Done()
			match := template.CompiledWorkflow.RunWorkflow(URL)
			results.CAS(false, match)
		}(URL)
		return nil
	})
	wg.Wait()
	return results.Load()
}
