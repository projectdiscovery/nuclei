package core

import (
	"fmt"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/clusterer"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"github.com/remeh/sizedwaitgroup"
	"github.com/rs/xid"
	"go.uber.org/atomic"
)

// Execute takes a list of templates/workflows that have been compiled
// and executes them based on provided concurrency options.
//
// All the execution logic for the templates/workflows happens in this part
// of the engine.
func (e *Engine) Execute(templates []*templates.Template, target InputProvider) *atomic.Bool {
	return e.ExecuteWithOpts(templates, target, false)
}

// ExecuteWithOpts is execute with the full options
func (e *Engine) ExecuteWithOpts(templatesList []*templates.Template, target InputProvider, noCluster bool) *atomic.Bool {
	var finalTemplates []*templates.Template
	if !noCluster {
		finalTemplates, _ = e.ClusterTemplates(templatesList)
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
		switch {
		case template.SelfContained:
			// Self Contained requests are executed here separately
			e.executeSelfContainedTemplateWithInput(template, results)
		default:
			// All other request types are executed here
			e.executeModelWithInput(templateType, template, target, results)
		}
		wg.Done()
	}
	e.workPool.Wait()
	return results
}

// processSelfContainedTemplates execute a self-contained template.
func (e *Engine) executeSelfContainedTemplateWithInput(template *templates.Template, results *atomic.Bool) {
	match, err := template.Executer.Execute("")
	if err != nil {
		gologger.Warning().Msgf("[%s] Could not execute step: %s\n", e.executerOpts.Colorizer.BrightBlue(template.ID), err)
	}
	results.CAS(false, match)
}

// executeModelWithInput executes a type of template with input
func (e *Engine) executeModelWithInput(templateType types.ProtocolType, template *templates.Template, input InputProvider, results *atomic.Bool) {
	wg := e.workPool.InputPool(templateType)

	input.Scan(func(scannedValue string) {
		// Skip if the host has had errors
		if e.executerOpts.HostErrorsCache != nil && e.executerOpts.HostErrorsCache.Check(scannedValue) {
			return
		}

		wg.Waitgroup.Add()
		go func(value string) {
			defer wg.Waitgroup.Done()

			var match bool
			var err error
			switch templateType {
			case types.WorkflowProtocol:
				match = e.executeWorkflow(value, template.CompiledWorkflow)
			default:
				match, err = template.Executer.Execute(value)
			}
			if err != nil {
				gologger.Warning().Msgf("[%s] Could not execute step: %s\n", e.executerOpts.Colorizer.BrightBlue(template.ID), err)
			}
			results.CAS(false, match)
		}(scannedValue)
	})
	wg.Waitgroup.Wait()
}

// ClusterTemplates performs identical http requests clustering for a list of templates
func (e *Engine) ClusterTemplates(templatesList []*templates.Template) ([]*templates.Template, int) {
	if e.options.OfflineHTTP {
		return templatesList, 0
	}

	templatesMap := make(map[string]*templates.Template)
	for _, v := range templatesList {
		templatesMap[v.Path] = v
	}
	clusterCount := 0

	finalTemplatesList := make([]*templates.Template, 0, len(templatesList))
	clusters := clusterer.Cluster(templatesMap)
	for _, cluster := range clusters {
		if len(cluster) > 1 {
			executerOpts := e.ExecuterOptions()

			clusterID := fmt.Sprintf("cluster-%s", xid.New().String())

			finalTemplatesList = append(finalTemplatesList, &templates.Template{
				ID:            clusterID,
				RequestsHTTP:  cluster[0].RequestsHTTP,
				Executer:      clusterer.NewExecuter(cluster, &executerOpts),
				TotalRequests: len(cluster[0].RequestsHTTP),
			})
			clusterCount += len(cluster)
		} else {
			finalTemplatesList = append(finalTemplatesList, cluster...)
		}
	}
	return finalTemplatesList, clusterCount
}
