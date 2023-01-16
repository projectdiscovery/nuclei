package core

import (
	"sync"

	"github.com/remeh/sizedwaitgroup"
	"go.uber.org/atomic"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/core/inputs"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

/*
Below Options specify some options on how to execute templates on targets
- Execute takes compiled templates/workflows and runs them on targets
*/

// Executes nuclei with default configuration
func (e *Engine) Execute(templates []*templates.Template, target InputProvider) *atomic.Bool {
	return e.ExecuteScanWithOpts(templates, target, false)
}

// ExecuteScanWithOpts executes scan with given scanStatergy
func (e *Engine) ExecuteScanWithOpts(templatesList []*templates.Template, target InputProvider, noCluster bool) *atomic.Bool {
	results := &atomic.Bool{}
	selfcontainedWg := &sync.WaitGroup{}

	var finalTemplates []*templates.Template
	if !noCluster {
		finalTemplates, _ = templates.ClusterTemplates(templatesList, e.executerOpts)
	} else {
		finalTemplates = templatesList
	}

	if stringsutil.EqualFoldAny(e.options.ScanStrategy, "auto", "") {
		// TODO: this is only a placeholder, auto scan strategy should choose scan strategy
		// based on no of hosts , templates , stream and other optimization parameters
		e.options.ScanStrategy = "template-spray"
	}

	filtered := []*templates.Template{}
	selfContained := []*templates.Template{}
	// Filter Self Contained templates since they are not bound to target
	for _, v := range finalTemplates {
		if v.SelfContained {
			selfContained = append(selfContained, v)
		} else {
			filtered = append(filtered, v)
		}
	}

	// Execute All SelfContained in parallel
	e.executeAllSelfContained(selfContained, results, selfcontainedWg)

	switch e.options.ScanStrategy {
	case "template-spray":
		results = e.executeTemplateSpray(filtered, target)
	case "host-spray":
		results = e.executeHostSpray(filtered, target)
	}

	selfcontainedWg.Wait()
	return results
}

// ExecuteWithResults a list of templates with results
func (e *Engine) ExecuteWithResults(templatesList []*templates.Template, target InputProvider, callback func(*output.ResultEvent)) *atomic.Bool {
	results := &atomic.Bool{}
	for _, template := range templatesList {
		templateType := template.Type()

		var wg *sizedwaitgroup.SizedWaitGroup
		if templateType == types.HeadlessProtocol {
			wg = e.workPool.Headless
		} else {
			wg = e.workPool.Default
		}

		wg.Add()
		go func(tpl *templates.Template) {
			e.executeModelWithInputAndResult(templateType, tpl, target, results, callback)
			wg.Done()
		}(template)
	}
	e.workPool.Wait()
	return results
}

// executeTemplateSpray executes scan using template spray strategy where targets are iterated over each template
func (e *Engine) executeTemplateSpray(templatesList []*templates.Template, target InputProvider) *atomic.Bool {
	results := &atomic.Bool{}

	templateswg := sizedwaitgroup.New(e.options.TemplateThreads + e.options.HeadlessTemplateThreads)
	// Max concurrent execution of headless templates on targets
	headlesswg := sizedwaitgroup.New(e.options.HeadlessTemplateThreads)
	// Max concurrent execution of templates other than headless
	otherwg := sizedwaitgroup.New(e.options.TemplateThreads)

	// get workpool returns workpool based on given template type
	getWorkpool := func(tpltype types.ProtocolType) *sizedwaitgroup.SizedWaitGroup {
		if tpltype == types.HeadlessProtocol {
			return &headlesswg
		} else {
			return &otherwg
		}
	}

	for _, template := range templatesList {
		templateswg.Add()
		go func(tpl *templates.Template) {
			defer templateswg.Done()
			wp := getWorkpool(tpl.Type())
			e.executeTemplateWithManyTargets(tpl, target, wp, results)
		}(template)
	}
	headlesswg.Wait()
	otherwg.Wait()
	templateswg.Wait()
	return results
}

// executeHostSpray executes scan using host spray strategy where templates are iterated over each target
func (e *Engine) executeHostSpray(templatesList []*templates.Template, target InputProvider) *atomic.Bool {
	results := &atomic.Bool{}
	hostwg := sizedwaitgroup.New(e.options.BulkSize + e.options.HeadlessBulkSize)
	// Max concurrent headless templates
	headlesswg := sizedwaitgroup.New(e.options.HeadlessTemplateThreads)
	// Max concurrent templates other than headless
	otherwg := sizedwaitgroup.New(e.options.TemplateThreads)

	// get workpool returns workpool based on given template type
	getWorkpool := func(tpltype types.ProtocolType) *sizedwaitgroup.SizedWaitGroup {
		if tpltype == types.HeadlessProtocol {
			return &headlesswg
		} else {
			return &otherwg
		}
	}

	target.Scan(func(value *contextargs.MetaInput) bool {
		host := inputs.SimpleInputProvider{
			Inputs: []*contextargs.MetaInput{
				value,
			},
		}
		// Goroutine for each host
		hostwg.Add()
		go func(inputtarget InputProvider) {
			defer hostwg.Done()

			// Now iterate and run all templates
			for _, tpl := range templatesList {
				wp := getWorkpool(tpl.Type())
				wp.Add()
				go e.executeTemplateWithOneTarget(tpl, value, wp, results)
			}

		}(&host)
		return true
	})

	headlesswg.Wait()
	otherwg.Wait()
	hostwg.Wait()
	return results
}

// executeModelWithInputAndResult executes a type of template with input and result
func (e *Engine) executeModelWithInputAndResult(templateType types.ProtocolType, template *templates.Template, target InputProvider, results *atomic.Bool, callback func(*output.ResultEvent)) {
	wg := e.workPool.InputPool(templateType)

	target.Scan(func(scannedValue *contextargs.MetaInput) bool {
		// Skip if the host has had errors
		if e.executerOpts.HostErrorsCache != nil && e.executerOpts.HostErrorsCache.Check(scannedValue.ID()) {
			return true
		}

		wg.WaitGroup.Add()
		go func(value *contextargs.MetaInput) {
			defer wg.WaitGroup.Done()

			var match bool
			var err error
			switch templateType {
			case types.WorkflowProtocol:
				match = e.executeWorkflow(value, template.CompiledWorkflow)
			default:
				ctxArgs := contextargs.New()
				ctxArgs.MetaInput = value
				err = template.Executer.ExecuteWithResults(ctxArgs, func(event *output.InternalWrappedEvent) {
					for _, result := range event.Results {
						callback(result)
					}
				})
			}
			if err != nil {
				gologger.Warning().Msgf("[%s] Could not execute step: %s\n", e.executerOpts.Colorizer.BrightBlue(template.ID), err)
			}
			results.CompareAndSwap(false, match)
		}(scannedValue)
		return true
	})
	wg.WaitGroup.Wait()
}
