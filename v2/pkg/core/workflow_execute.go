package core

import (
	"github.com/remeh/sizedwaitgroup"
	"go.uber.org/atomic"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/workflows"
)

// executeWorkflow runs a workflow on an input and returns true or false
func (e *Engine) executeWorkflow(input string, w *workflows.Workflow) bool {
	results := &atomic.Bool{}

	swg := sizedwaitgroup.New(w.Options.Options.TemplateThreads)
	for _, template := range w.Workflows {
		swg.Add()

		func(template *workflows.WorkflowTemplate) {
			if err := e.runWorkflowStep(&runWorkflowStepArgs{
				template:      template,
				input:         input,
				results:       results,
				swg:           &swg,
				w:             w,
				previous:      make(output.InternalEvent),
				dynamicValues: make(output.InternalEvent),
			}); err != nil {
				gologger.Warning().Msgf("[%s] Could not execute workflow step: %s\n", template.Template, err)
			}
			swg.Done()
		}(template)
	}
	swg.Wait()
	return results.Load()
}

// runWorkflowStepArgs are the arguments for workflow template execution
type runWorkflowStepArgs struct {
	template      *workflows.WorkflowTemplate
	input         string
	results       *atomic.Bool
	swg           *sizedwaitgroup.SizedWaitGroup
	w             *workflows.Workflow
	previous      output.InternalEvent
	dynamicValues output.InternalEvent
}

// Copy returns a copy of the runWorkflowStepArgs structure
func (r *runWorkflowStepArgs) Copy() *runWorkflowStepArgs {
	return &runWorkflowStepArgs{
		template:      r.template,
		input:         r.input,
		results:       r.results,
		swg:           r.swg,
		w:             r.w,
		previous:      r.previous,
		dynamicValues: r.dynamicValues,
	}
}

// runWorkflowStep runs a workflow step for the workflow. It executes the workflow
// in a recursive manner running all subtemplates and matchers.
func (e *Engine) runWorkflowStep(workflowArgs *runWorkflowStepArgs) error {
	var firstMatched bool
	var err error
	var mainErr error
	var finalEvent output.InternalEvent

	if len(workflowArgs.template.Matchers) == 0 {
		if firstMatched, finalEvent, err = e.executeWorkflowStepNoMatchers(workflowArgs); err != nil {
			mainErr = err
		}
		if workflowArgs.template.CaptureValues {
			workflowArgs.dynamicValues = finalEvent
		}
	}
	if len(workflowArgs.template.Subtemplates) == 0 {
		workflowArgs.results.CAS(false, firstMatched)
	}
	if len(workflowArgs.template.Matchers) > 0 {
		if err := e.executeWorkflowStepMatchers(workflowArgs); err != nil {
			mainErr = err
		}
	}
	if len(workflowArgs.template.Subtemplates) > 0 && (firstMatched || workflowArgs.template.CaptureValues) {
		e.executeWorkflowStepSubtemplates(workflowArgs)
	}
	return mainErr
}

// executeWorkflowStepNoMatchers executes workflow step for condition with no matchers.
func (e *Engine) executeWorkflowStepNoMatchers(workflowArgs *runWorkflowStepArgs) (bool, output.InternalEvent, error) {
	var firstMatched bool
	var err error
	finalEvent := workflowArgs.dynamicValues
	var mainErr error

	for _, executer := range workflowArgs.template.Executers {
		executer.Options.Progress.AddToTotal(int64(executer.Executer.Requests()))

		// Don't print results with subtemplates, only print results on template.
		if len(workflowArgs.template.Subtemplates) > 0 {
			err = executer.Executer.ExecuteWithResults(workflowArgs.input, finalEvent, workflowArgs.previous, func(result *output.InternalWrappedEvent) {
				if result.OperatorsResult == nil {
					return
				}
				if len(result.Results) > 0 {
					firstMatched = true
				}
				if len(result.OperatorsResult.DynamicValues) > 0 && workflowArgs.template.CaptureValues {
					finalEvent = generators.MergeMaps(finalEvent, result.OperatorsResult.DynamicValues)
				}
			})
		} else {
			var matched bool
			matched, err = executer.Executer.Execute(workflowArgs.input, finalEvent, workflowArgs.previous)
			if matched {
				firstMatched = true
			}
		}
		if err != nil {
			if workflowArgs.w.Options.HostErrorsCache != nil {
				if workflowArgs.w.Options.HostErrorsCache.CheckError(err) {
					workflowArgs.w.Options.HostErrorsCache.MarkFailed(workflowArgs.input)
				}
			}
			if len(workflowArgs.template.Executers) == 1 {
				mainErr = err
			} else {
				gologger.Warning().Msgf("[%s] Could not execute workflow step: %s\n", workflowArgs.template.Template, err)
			}
			continue
		}
	}
	return firstMatched, finalEvent, mainErr
}

// executeWorkflowStepMatchers executes workflow step for condition with matchers
func (e *Engine) executeWorkflowStepMatchers(workflowArgs *runWorkflowStepArgs) error {
	var mainErr error

	for _, executer := range workflowArgs.template.Executers {
		executer.Options.Progress.AddToTotal(int64(executer.Executer.Requests()))

		err := executer.Executer.ExecuteWithResults(workflowArgs.input, workflowArgs.dynamicValues, workflowArgs.previous, func(event *output.InternalWrappedEvent) {
			if event.OperatorsResult == nil {
				return
			}

			for _, matcher := range workflowArgs.template.Matchers {
				_, matchOK := event.OperatorsResult.Matches[matcher.Name]
				_, extractOK := event.OperatorsResult.Extracts[matcher.Name]
				if !matchOK && !extractOK {
					continue
				}

				for _, subtemplate := range matcher.Subtemplates {
					workflowArgs.swg.Add()

					go func(subtemplate *workflows.WorkflowTemplate) {
						copy := workflowArgs.Copy()
						copy.template = subtemplate

						if err := e.runWorkflowStep(copy); err != nil {
							gologger.Warning().Msgf("[%s] Could not execute workflow step: %s\n", subtemplate.Template, err)
						}
						workflowArgs.swg.Done()
					}(subtemplate)
				}
			}
		})
		if err != nil {
			if len(workflowArgs.template.Executers) == 1 {
				mainErr = err
			} else {
				gologger.Warning().Msgf("[%s] Could not execute workflow step: %s\n", workflowArgs.template.Template, err)
			}
			continue
		}
	}
	return mainErr
}

// executeWorkflowStepSubtemplates executes workflow step for condition with subtemplates
func (e *Engine) executeWorkflowStepSubtemplates(workflowArgs *runWorkflowStepArgs) {
	for _, subtemplate := range workflowArgs.template.Subtemplates {
		workflowArgs.swg.Add()

		go func(template *workflows.WorkflowTemplate) {
			copy := workflowArgs.Copy()
			copy.template = template

			if err := e.runWorkflowStep(copy); err != nil {
				gologger.Warning().Msgf("[%s] Could not execute workflow step: %s\n", template.Template, err)
			}
			workflowArgs.swg.Done()
		}(subtemplate)
	}
}
