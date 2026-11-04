package runner

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestPlanRejectsOptionsThatChangeTargetsLater(t *testing.T) {
	for name, options := range map[string]*types.Options{
		"automatic scan": {PlanFile: "p", AutomaticScan: true},
		"uncover":        {PlanFile: "p", Uncover: true},
		"preflight":      {PlanFile: "p", PreflightPortScan: true},
	} {
		require.Error(t, validatePlanOptions(options), name)
	}
	require.NoError(t, validatePlanOptions(&types.Options{PlanFile: "p"}))
	require.NoError(t, validatePlanOptions(&types.Options{Uncover: true}), "only -plan restricts them")
}
