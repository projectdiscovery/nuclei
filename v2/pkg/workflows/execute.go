package workflows

import "go.uber.org/atomic"

// RunWorkflow runs a workflow on an input and returns true or false
func (w *Workflow) RunWorkflow(input string) (bool, error) {
	results := &atomic.Bool{}

	for _, template := range w.Workflows {
		err := w.runWorkflowStep(template, input, results)
		if err != nil {
			return false, err
		}
	}
	return results.Load(), nil
}

// runWorkflowStep runs a workflow step for the workflow. It executes the workflow
// in a recursive manner running all subtemplates and matchers.
func (w *Workflow) runWorkflowStep(template *WorkflowTemplate, input string, results *atomic.Bool) error {
	var firstMatched bool
	if len(template.Matchers) == 0 {
		matched, err := template.executer.Execute(input)
		if err != nil {
			return err
		}
		firstMatched = matched
		results.CAS(false, matched)
	}

	if len(template.Matchers) > 0 {
		output, err := template.executer.ExecuteWithResults(input)
		if err != nil {
			return err
		}
		if len(output) == 0 {
			return nil
		}

		for _, matcher := range template.Matchers {
			for _, item := range output {
				if item.OperatorsResult == nil {
					continue
				}

				_, matchOK := item.OperatorsResult.Matches[matcher.Name]
				_, extractOK := item.OperatorsResult.Extracts[matcher.Name]
				if !matchOK && !extractOK {
					continue
				}

				for _, subtemplate := range matcher.Subtemplates {
					if err := w.runWorkflowStep(subtemplate, input, results); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	if len(template.Subtemplates) > 0 && firstMatched {
		for _, subtemplate := range template.Subtemplates {
			if err := w.runWorkflowStep(subtemplate, input, results); err != nil {
				return err
			}
		}
	}
	return nil
}
