package plan

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/types/scanstrategy"
	"github.com/stretchr/testify/require"
)

func TestDecideStrategyHostSpray(t *testing.T) {
	p := Decide(Input{
		Hosts:     5,
		Templates: 200,
		Requests:  10000,
		BulkSize:  25,
	})
	require.Equal(t, scanstrategy.HostSpray.String(), p.Strategy)
	require.Contains(t, p.Reason, "strategy=host-spray")
}

func TestDecideStrategyTemplateSpraySmallBench(t *testing.T) {
	p := Decide(Input{
		Hosts:     5,
		Templates: 100,
		Requests:  500,
		BulkSize:  25,
	})
	require.Equal(t, scanstrategy.TemplateSpray.String(), p.Strategy)
}

func TestDecideStrategyTemplateSprayManyHosts(t *testing.T) {
	p := Decide(Input{
		Hosts:     1000,
		Templates: 50,
		Requests:  50000,
		BulkSize:  25,
	})
	require.Equal(t, scanstrategy.TemplateSpray.String(), p.Strategy)
}

func TestDecideStrategyStreamDefaultsTemplateSpray(t *testing.T) {
	p := Decide(Input{
		Hosts:     5,
		Templates: 100,
		Stream:    true,
		BulkSize:  25,
	})
	require.Equal(t, scanstrategy.TemplateSpray.String(), p.Strategy)
}

func TestDecideReachabilityOffWithoutStrictProbe(t *testing.T) {
	p := Decide(Input{
		Hosts:        5,
		Templates:    60,
		Requests:     300,
		StrictProbe:  false,
		PortsToProbe: 3,
	})
	require.False(t, p.BuildReachability)
	require.False(t, p.UseReachabilityFilter)
	require.Contains(t, p.Reason, "reachability=off")
}

func TestDecideReachabilityHTTPOnly(t *testing.T) {
	p := Decide(Input{
		Hosts:                    5,
		Templates:                60,
		Requests:                 300,
		StrictProbe:              true,
		PortsToProbe:             0,
		ConcreteNetworkTemplates: 0,
	})
	require.True(t, p.BuildReachability)
	require.False(t, p.ProbePorts)
	require.True(t, p.UseReachabilityFilter)
	require.Contains(t, p.Reason, "reachability=http-only")
}

func TestDecideReachabilityProbeBudgetSkip(t *testing.T) {
	p := Decide(Input{
		Hosts:                    100,
		Templates:                10,
		Requests:                 1000,
		StrictProbe:              true,
		PortsToProbe:             50, // cost = 5000 > 2*baseline
		ConcreteNetworkTemplates: 5,
		GroupCount:               0,
	})
	require.False(t, p.BuildReachability)
	require.False(t, p.UseReachabilityFilter)
	require.Contains(t, p.Reason, "reachability=skipped-probe-budget")
}

func TestDecideReachabilityFull(t *testing.T) {
	p := Decide(Input{
		Hosts:                    5,
		Templates:                60,
		Requests:                 300,
		StrictProbe:              true,
		PortsToProbe:             3, // cost = 15 << baseline
		ConcreteNetworkTemplates: 30,
	})
	require.True(t, p.BuildReachability)
	require.True(t, p.ProbePorts)
	require.True(t, p.UseReachabilityFilter)
	require.Contains(t, p.Reason, "reachability=full")
}

func TestDecideReachabilityEmptyInput(t *testing.T) {
	p := Decide(Input{StrictProbe: true, Hosts: 0, Templates: 10})
	require.False(t, p.BuildReachability)
	require.Contains(t, p.Reason, "reachability=skipped-empty")
}

func TestDecideReachabilityConcreteZeroUsesHTTPOnly(t *testing.T) {
	p := Decide(Input{
		Hosts:                    20,
		Templates:                100,
		Requests:                 2000,
		StrictProbe:              true,
		PortsToProbe:             5,
		ConcreteNetworkTemplates: 0, // web-only set
	})
	require.True(t, p.BuildReachability)
	require.False(t, p.ProbePorts)
	require.True(t, p.UseReachabilityFilter)
}

func TestDecideHostSprayRequiresLargeRequestBudget(t *testing.T) {
	// hosts small + many templates but requests below threshold → template-spray
	p := Decide(Input{
		Hosts:     5,
		Templates: 200,
		Requests:  4999,
		BulkSize:  25,
	})
	require.Equal(t, scanstrategy.TemplateSpray.String(), p.Strategy)
}

func TestDecideApplyFilteredIgnoredWhenZero(t *testing.T) {
	p := Decide(Input{
		Hosts:            5,
		Templates:        10,
		Requests:         50,
		StrictProbe:      false,
		FilteredRequests: 0,
	})
	require.Equal(t, int64(50), p.ExpectedRequests)
	p.ApplyFiltered(0)
	require.Equal(t, int64(50), p.ExpectedRequests)
	p.ApplyFiltered(12)
	require.Equal(t, int64(12), p.ExpectedRequests)
}

func TestDecideTechFilterOffByDefault(t *testing.T) {
	p := Decide(Input{
		Hosts:              5,
		Templates:          100,
		Requests:           500,
		TechFilter:         false,
		TechBoundTemplates: 40,
	})
	require.False(t, p.UseTechFilter)
	require.Contains(t, p.Reason, "tech-filter=off")
}

func TestDecideTechFilterSkippedWhenNoBound(t *testing.T) {
	p := Decide(Input{
		Hosts:              5,
		Templates:          100,
		Requests:           500,
		TechFilter:         true,
		TechBoundTemplates: 0,
	})
	require.False(t, p.UseTechFilter)
	require.Contains(t, p.Reason, "tech-filter=skipped-no-bound-templates")
}

func TestDecideTechFilterOn(t *testing.T) {
	p := Decide(Input{
		Hosts:              5,
		Templates:          100,
		Requests:           500,
		TechFilter:         true,
		TechBoundTemplates: 40,
	})
	require.True(t, p.UseTechFilter)
	require.Contains(t, p.Reason, "tech-filter=on")
}
