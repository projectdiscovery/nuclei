package workflows

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"go.uber.org/atomic"
)

// RunWorkflow runs a workflow on an input and returns true or false
func (w *Workflow) RunWorkflow(input string) (bool, error) {
	results := &atomic.Bool{}

	for _, template := range w.Workflows {
		err := w.runWorkflowStep(template, input, results)
		if err != nil {
			return results.Load(), err
		}
	}
	return results.Load(), nil
}

// runWorkflowStep runs a workflow step for the workflow. It executes the workflow
// in a recursive manner running all subtemplates and matchers.
func (w *Workflow) runWorkflowStep(template *WorkflowTemplate, input string, results *atomic.Bool) error {
	var firstMatched bool

	var mainErr error
	if len(template.Matchers) == 0 {
		for _, executer := range template.Executers {
			executer.Options.Progress.AddToTotal(int64(executer.Executer.Requests()))

			matched, err := executer.Executer.Execute(input)
			if err != nil {
				if len(template.Executers) == 1 {
					mainErr = err
				} else {
					gologger.Warning().Msgf("[%s] Could not execute workflow step: %s\n", template.Template, err)
				}
				continue
			}
			if matched {
				firstMatched = matched
				results.CAS(false, matched)
			}
		}
	}

	if len(template.Matchers) > 0 {
		var executionErr error
		var mainErr error

		for _, executer := range template.Executers {
			executer.Options.Progress.AddToTotal(int64(executer.Executer.Requests()))

			err := executer.Executer.ExecuteWithResults(input, func(event *output.InternalWrappedEvent) {
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
						if err := w.runWorkflowStep(subtemplate, input, results); err != nil {
							executionErr = err
							break
						}
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
			if executionErr != nil {
				if len(template.Executers) == 1 {
					mainErr = executionErr
				} else {
					gologger.Warning().Msgf("[%s] Could not execute workflow step: %s\n", template.Template, executionErr)
				}
			}
		}
		return mainErr
	}
	if len(template.Subtemplates) > 0 && firstMatched {
		for _, subtemplate := range template.Subtemplates {
			if err := w.runWorkflowStep(subtemplate, input, results); err != nil {
				return err
			}
		}
	}
	return mainErr
}
