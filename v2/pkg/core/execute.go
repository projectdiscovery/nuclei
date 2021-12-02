package core

import (
	"github.com/remeh/sizedwaitgroup"
	"go.uber.org/atomic"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
)

// Execute takes a list of templates/workflows that have been compiled
// and executes them based on provided concurrency options.
//
// All the execution logic for the templates/workflows happens in this part
// of the engine.
func (e *Engine) Execute(templates []*templates.Template, target InputProvider) *atomic.Bool {
	return e.ExecuteWithOpts(templates, target, false)
}

// ExecuteWithOpts executes with the full options
func (e *Engine) ExecuteWithOpts(templatesList []*templates.Template, target InputProvider, noCluster bool) *atomic.Bool {
	var finalTemplates []*templates.Template
	if !noCluster {
		finalTemplates, _ = templates.ClusterTemplates(templatesList, e.executerOpts)
	} else {
		finalTemplates = templatesList
	}

	results := &atomic.Bool{}
	for _, template := range finalTemplates {
		templateType := template.Type()

		var wg *sizedwaitgroup.SizedWaitGroup
		if templateType == types.HeadlessProtocol {
			wg = e.workPool.Headless
		} else {
			wg = e.workPool.Default
		}

		wg.Add()
		go func(tpl *templates.Template) {
			switch {
			case tpl.SelfContained:
				// Self Contained requests are executed here separately
				e.executeSelfContainedTemplateWithInput(tpl, results)
			default:
				// All other request types are executed here
				e.executeModelWithInput(templateType, tpl, target, results)
			}
			wg.Done()
		}(template)
	}
	e.workPool.Wait()
	return results
}

// processSelfContainedTemplates execute a self-contained template.
func (e *Engine) executeSelfContainedTemplateWithInput(template *templates.Template, results *atomic.Bool) {
	match, err := template.Executer.Execute("", make(output.InternalEvent), make(output.InternalEvent))
	if err != nil {
		gologger.Warning().Msgf("[%s] Could not execute step: %s\n", e.executerOpts.Colorizer.BrightBlue(template.ID), err)
	}
	results.CAS(false, match)
}

// executeModelWithInput executes a type of template with input
func (e *Engine) executeModelWithInput(templateType types.ProtocolType, template *templates.Template, target InputProvider, results *atomic.Bool) {
	wg := e.workPool.InputPool(templateType)

	target.Scan(func(scannedValue string) {
		// Skip if the host has had errors
		if e.executerOpts.HostErrorsCache != nil && e.executerOpts.HostErrorsCache.Check(scannedValue) {
			return
		}

		wg.WaitGroup.Add()
		go func(value string) {
			defer wg.WaitGroup.Done()

			var match bool
			var err error
			switch templateType {
			case types.WorkflowProtocol:
				match = e.executeWorkflow(value, template.CompiledWorkflow)
			default:
				match, err = template.Executer.Execute(value, make(output.InternalEvent), make(output.InternalEvent))
			}
			if err != nil {
				gologger.Warning().Msgf("[%s] Could not execute step: %s\n", e.executerOpts.Colorizer.BrightBlue(template.ID), err)
			}
			results.CAS(false, match)
		}(scannedValue)
	})
	wg.WaitGroup.Wait()
}
