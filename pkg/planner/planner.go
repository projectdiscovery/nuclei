package planner

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/catalogue"
	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/workflows"
)

// ExecutionPlan is the execution plan of a certain scan input.
type ExecutionPlan struct {
	steps []*Step
}

// Plan plans the execution flow of a scan using input quarks.
func Plan(inputs []*catalogue.CompiledInput) (*ExecutionPlan, error) {
	plan := &ExecutionPlan{
		steps: make([]*Step, 0, len(inputs)),
	}

	for _, input := range inputs {
		if input.Type == catalogue.TemplateInputType {
			plan.planTemplate(input)
		} else if input.Type == catalogue.WorkflowInputType {
			plan.planWorkflow(input)
		}
	}
	return plan, nil
}

// planTemplate plans a template into the execution plan
func (e *ExecutionPlan) planTemplate(input *catalogue.CompiledInput) {
	e.steps = append(e.steps, &Step{
		Type:      TemplateStepType,
		Templates: []*templates.CompiledTemplate{input.CompiledTemplate},
	})
}

// planWorkflow plans a workflow into the execution plan
func (e *ExecutionPlan) planWorkflow(input *catalogue.CompiledInput) {
	e.steps = append(e.steps, &Step{
		Type:      WorkflowStepType,
		Workflows: []*workflows.CompiledWorkflow{input.CompiledWorkflow},
	})
}

func (e *ExecutionPlan) planTemplateDNSRequests(input *catalogue.CompiledInput) {
	//	for _, dns := range input.DNS {
	//		//	for _, request := range dns.AtomicRequests {
	//		//		for _, step := range e.steps {
	//		//
	//		//		}
	//		//	}
	//	}
}
