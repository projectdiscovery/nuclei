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

func TestDecideApplyFiltered(t *testing.T) {
	p := Decide(Input{
		Hosts:                    5,
		Templates:                60,
		Requests:                 300,
		StrictProbe:              true,
		FilteredRequests:         105,
		PortsToProbe:             3,
		ConcreteNetworkTemplates: 30,
	})
	require.Equal(t, int64(105), p.ExpectedRequests)
}
