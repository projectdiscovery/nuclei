package planner

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/quarks"
	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/input"
)

// ExecutionPlan is the execution plan of a certain scan input.
type ExecutionPlan struct {
	// Flow is the scan flow defined in the form a quark execution graph.
	Flow []quarks.CompiledQuark
}

// PlanExecution plans the execution flow of a scan using input quarks.
func PlanExecution(quarks []input.Input) (*ExecutionPlan, error) {
	for _, quark := range quarks {

	}
	// Compile all the quarks into
}
