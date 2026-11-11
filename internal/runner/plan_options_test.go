package runner

import (
	"testing"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestPlanRejectsOptionsThatChangeTargetsLater(t *testing.T) {
	for name, options := range map[string]*types.Options{
		"automatic scan": {PlanFile: "p", AutomaticScan: true},
		"uncover":        {PlanFile: "p", Uncover: true},
		"uncover query":  {PlanFile: "p", UncoverQuery: goflags.StringSlice{"example"}},
		"preflight":      {PlanFile: "p", PreflightPortScan: true},
		"dast server":    {PlanFile: "p", DASTServer: true},
		"dast proxy":     {PlanFile: "p", DASTProxy: true},
	} {
		require.Error(t, validatePlanOptions(options), name)
	}
	require.NoError(t, validatePlanOptions(&types.Options{PlanFile: "p"}))
	require.NoError(t, validatePlanOptions(&types.Options{Uncover: true}), "only -plan restricts them")
	require.NoError(t, validatePlanOptions(&types.Options{UncoverQuery: goflags.StringSlice{"example"}}))
	require.NoError(t, validatePlanOptions(&types.Options{DASTServer: true}))

	require.Error(t, validatePlanOptions(&types.Options{RunPlanFile: "p", PlanFile: "q"}))
	require.Error(t, validatePlanOptions(&types.Options{RunPlanFile: "p", Resume: "r"}))
	require.NoError(t, validatePlanOptions(&types.Options{RunPlanFile: "p"}))

	for name, options := range map[string]*types.Options{
		"run automatic scan": {RunPlanFile: "p", AutomaticScan: true},
		"run uncover":        {RunPlanFile: "p", Uncover: true},
		"run uncover query":  {RunPlanFile: "p", UncoverQuery: goflags.StringSlice{"example"}},
		"run preflight":      {RunPlanFile: "p", PreflightPortScan: true},
		"run dast server":    {RunPlanFile: "p", DASTServer: true},
		"run dast proxy":     {RunPlanFile: "p", DASTProxy: true},
	} {
		require.Error(t, validatePlanOptions(options), name)
	}
}
