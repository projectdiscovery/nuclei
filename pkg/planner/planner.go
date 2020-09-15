package planner

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/catalogue"
	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/requests/http"
)

// ExecutionPlan is the execution plan of a certain scan input.
type ExecutionPlan struct {
	// Flow is the scan flow defined in the form a quark execution graph.
	//Inputs
	httpRequests []*http.CompiledRequest
}

// ExecutionStep defines a single step to be performed during execution
type ExecutionStep struct {
}

// Plan plans the execution flow of a scan using input quarks.
func Plan(inputs []*catalogue.CompiledInput) (*ExecutionPlan, error) {
	plan := &ExecutionPlan{}

	for _, input := range inputs {
		if input.Type == catalogue.TemplateInputType {
			plan.planTemplate(input)
		}
	}
}

// planTemplate plans a template into the execution plan
func (e *ExecutionPlan) planTemplate(input *catalogue.CompiledInput) {
}
