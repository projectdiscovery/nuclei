package plan

import (
	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/types/scanstrategy"
)

// Input is the scan shape the planner uses to pick strategy and reachability.
type Input struct {
	Hosts       int
	Templates   int
	Requests    int // template×host request estimate (baseline)
	BulkSize    int
	Stream      bool
	StrictProbe bool

	// Reachability / probe budget (known before or after probing).
	PortsToProbe             int
	ConcreteNetworkTemplates int
	// FilteredRequests, when > 0, is the post-filter request estimate used for Progress.Init.
	FilteredRequests int
	// GroupCount is distinct host signatures after probing (0 = unknown).
	GroupCount int
}

// Plan is the execution plan for a single scan pass.
type Plan struct {
	Strategy              string
	BuildReachability     bool
	ProbePorts            bool
	UseReachabilityFilter bool
	ExpectedRequests      int64
	Reason                string
}

// Decide chooses spray strategy and whether to spend budget on reachability probing.
//
// Hard bar: never choose work that is expected to regress wall clock vs baseline spray.
// When probe cost would dominate and savings are uncertain, reachability is skipped.
func Decide(in Input) Plan {
	p := Plan{
		Strategy:         chooseStrategy(in),
		ExpectedRequests: int64(max(in.Requests, 0)),
	}

	stratReason := strategyReason(in, p.Strategy)
	if !in.StrictProbe {
		p.Reason = stratReason + "; reachability=off"
		return p
	}

	reach := decideReachability(in)
	p.BuildReachability = reach.build
	p.ProbePorts = reach.probePorts
	p.UseReachabilityFilter = reach.useFilter
	p.Reason = stratReason + "; " + reach.reason

	if in.FilteredRequests > 0 {
		p.ExpectedRequests = int64(in.FilteredRequests)
	}
	return p
}

func chooseStrategy(in Input) string {
	if in.Stream || in.Hosts <= 0 || in.Templates <= 0 {
		return scanstrategy.TemplateSpray.String()
	}
	bulk := in.BulkSize
	if bulk <= 0 {
		bulk = 25
	}
	// Host-spray only when the shape strongly favors per-host locality.
	// Conservative default is template-spray (historical auto) so wall clock
	// does not regress on small / mixed benches.
	if in.Hosts <= bulk && in.Hosts <= 10 && in.Templates >= 10*in.Hosts && in.Requests >= 5000 {
		return scanstrategy.HostSpray.String()
	}
	return scanstrategy.TemplateSpray.String()
}

func strategyReason(in Input, strategy string) string {
	return fmt.Sprintf("strategy=%s hosts=%d templates=%d", strategy, in.Hosts, in.Templates)
}

type reachabilityDecision struct {
	build      bool
	probePorts bool
	useFilter  bool
	reason     string
}

func decideReachability(in Input) reachabilityDecision {
	if in.Hosts <= 0 || in.Templates <= 0 {
		return reachabilityDecision{reason: "reachability=skipped-empty"}
	}

	probeCost := in.PortsToProbe * in.Hosts
	baseline := in.Requests
	if baseline <= 0 {
		baseline = in.Templates * in.Hosts
	}

	// No concrete network ports to probe: HTTP-only index is cheap (reuse httpx map).
	if in.PortsToProbe == 0 || in.ConcreteNetworkTemplates == 0 {
		return reachabilityDecision{
			build:      true,
			probePorts: false,
			useFilter:  true,
			reason:     "reachability=http-only",
		}
	}

	// Probe budget: if dialing every port×host costs more than the scan itself
	// and we have no signal of a mixed fleet, skip probing to match baseline time.
	if probeCost > baseline && in.GroupCount <= 1 {
		// GroupCount==0 (unknown) or 1 (homogeneous): do not pay for probes.
		if probeCost > max(baseline*2, 500) {
			return reachabilityDecision{
				reason: fmt.Sprintf("reachability=skipped-probe-budget cost=%d baseline=%d", probeCost, baseline),
			}
		}
	}

	// After probing, homogeneous fleets still benefit from a cheap filter (no extra dials
	// during spray for closed-port templates that global prune may have kept).
	return reachabilityDecision{
		build:      true,
		probePorts: true,
		useFilter:  true,
		reason:     fmt.Sprintf("reachability=full probe_cost=%d", probeCost),
	}
}

// ApplyFiltered updates ExpectedRequests once post-probe estimates are known.
func (p *Plan) ApplyFiltered(filtered int) {
	if filtered > 0 {
		p.ExpectedRequests = int64(filtered)
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
