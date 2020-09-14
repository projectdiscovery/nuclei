package planner

import "github.com/projectdiscovery/nuclei/v2/pkg/quarks"

// ExecutionPlan is the execution plan of a certain scan input.
type ExecutionPlan struct {
	// Flow is the scan flow defined in the form a quark execution graph.
	Flow []quarks.CompiledQuark
}

// PlanExecution plans the execution flow of a scan using input quarks.
func PlanExecution(quarks []quarks.Quark) (*ExecutionPlan, error) {

	// Compile all the quarks into
}
