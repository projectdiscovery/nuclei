package core

import (
	"github.com/remeh/sizedwaitgroup"
	"go.uber.org/atomic"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/workflows"
)

// executeWorkflow runs a workflow on an input and returns true or false
func (e *Engine) executeWorkflow(input string, w *workflows.Workflow) bool {
	results := &atomic.Bool{}

	swg := sizedwaitgroup.New(w.Options.Options.TemplateThreads)
	for _, template := range w.Workflows {
		swg.Add()
		func(template *workflows.WorkflowTemplate) {
			if err := w.runWorkflowStep(template, input, nil, results, &swg, w); err != nil {
				gologger.Warning().Msgf("[%s] Could not execute workflow step: %s\n", template.Template, err)
			}
			swg.Done()
		}(template)
	}
	swg.Wait()
	return results.Load()
}

// runWorkflowStep runs a workflow step for the workflow. It executes the workflow
// in a recursive manner running all subtemplates and matchers.
func (e *Engine) runWorkflowStep(template *workflows.WorkflowTemplate, input string, params map[string]interface{}, results *atomic.Bool, swg *sizedwaitgroup.SizedWaitGroup, w *workflows.Workflow) error {
	var firstMatched bool
	var err error
	var mainErr error

	if len(template.Matchers) == 0 {
		for _, executer := range template.Executers {
			executer.Options.Progress.AddToTotal(int64(executer.Executer.Requests()))

			// Don't print results with subtemplates, only print results on template.
			if len(template.Subtemplates) > 0 {
				err = executer.Executer.ExecuteWithResults(input, params, func(result *output.InternalWrappedEvent) {
					if result.OperatorsResult == nil {
						return
					}
					if len(result.Results) > 0 {
						firstMatched = true
					}

					// store the global values regardless of outcome
					for k, v := range result.OperatorsResult.GlobalValues {
						executer.Options.Store.Set(k, v)
					}
					if len(result.OperatorsResult.ParametrizedValues) > 0 {
						params = result.OperatorsResult.ParametrizedValues
					}
				})
			} else {
				var matched bool
				matched, err = executer.Executer.Execute(input, params)
				if matched {
					firstMatched = true
				}
			}
			if err != nil {
				if w.Options.HostErrorsCache != nil {
					if w.Options.HostErrorsCache.CheckError(err) {
						w.Options.HostErrorsCache.MarkFailed(input)
					}
				}
				if len(template.Executers) == 1 {
					mainErr = err
				} else {
					gologger.Warning().Msgf("[%s] Could not execute workflow step: %s\n", template.Template, err)
				}
				continue
			}
		}
	}
	if len(template.Subtemplates) == 0 {
		results.CAS(false, firstMatched)
	}
	if len(template.Matchers) > 0 {
		for _, executer := range template.Executers {
			executer.Options.Progress.AddToTotal(int64(executer.Executer.Requests()))
			err := executer.Executer.ExecuteWithResults(input, params, func(event *output.InternalWrappedEvent) {
				if event.OperatorsResult == nil {
					return
				}

				for _, matcher := range template.Matchers {
					_, matchOK := event.OperatorsResult.Matches[matcher.Name]
					_, extractOK := event.OperatorsResult.Extracts[matcher.Name]
					if !matchOK && !extractOK {
						continue
					}

					for _, subtemplate := range matcher.Subtemplates {
						swg.Add()

						// TODO: concurrency in subtemplates must be removed for parametric ones
						go func(subtemplate *workflows.WorkflowTemplate) {
							if err := e.runWorkflowStep(subtemplate, input, params, results, swg, w); err != nil {
								gologger.Warning().Msgf("[%s] Could not execute workflow step: %s\n", subtemplate.Template, err)
							}
							swg.Done()
						}(subtemplate)
					}
				}
			})
			if err != nil {
				if len(template.Executers) == 1 {
					mainErr = err
				} else {
					gologger.Warning().Msgf("[%s] Could not execute workflow step: %s\n", template.Template, err)
				}
				continue
			}
		}
		return mainErr
	}
	if len(template.Subtemplates) > 0 && firstMatched {
		for _, subtemplate := range template.Subtemplates {
			swg.Add()
			// TODO: meaningless concurrency with parameters dependency
			go func(template *workflows.WorkflowTemplate) {
				if err := e.runWorkflowStep(template, input, params, results, swg, w); err != nil {
					gologger.Warning().Msgf("[%s] Could not execute workflow step: %s\n", template.Template, err)
				}
				swg.Done()
			}(subtemplate)
		}
	}
	return mainErr
}
