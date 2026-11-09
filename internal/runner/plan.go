package runner

import (
	"bufio"
	"os"
	"slices"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/core"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

// httpRequestSeconds is the time of one http request the plan costs are
// weighted against (see core.PlanEntry.Cost).
const httpRequestSeconds = 0.015

// planSummary is the last line of a plan file, written once every entry is
// known.
type planSummary struct {
	Entries int `json:"entries"`
	// Alternatives are entries that run only when another of their origin
	// fails, so they are left out of every other total.
	Alternatives int `json:"alternatives,omitempty"`
	Requests     int `json:"requests"`
	Cost         int `json:"cost"`
	// EstimatedSeconds is the largest of the time the rate limit allows, the
	// cost spread over every concurrent slot, and the longest entry, whose
	// requests run one after another. Hosts slower than the measured request
	// time make the scan take longer.
	EstimatedSeconds int `json:"estimated-seconds"`
}

// writePlan writes one JSON line per unit of work the scan would run,
// followed by the summary. Targets are listed as given: inputs that the scan
// would probe to an http url first are not probed here, since probing sends
// requests.
func (r *Runner) writePlan(store *loader.Store, engine *core.Engine) error {
	if !r.options.DisableHTTPProbe && loader.IsHTTPBasedProtocolUsed(store) && r.isInputNonHTTP() {
		r.Logger.Info().Msgf("Targets without a scheme are planned as given; the scan probes them for http(s) first")
	}
	file, err := os.Create(r.options.PlanFile)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	writer := bufio.NewWriter(file)
	encoder := json.NewEncoder(writer)

	var summary planSummary
	var headlessCost, longest int
	var encodeErr error
	engine.Plan(slices.Concat(store.Templates(), store.Workflows()), r.inputProvider, r.options.DisableClustering, func(entry core.PlanEntry) {
		if encodeErr != nil {
			return
		}
		encodeErr = encoder.Encode(entry)
		if entry.AlternativeTo != "" {
			summary.Alternatives++
			return
		}
		summary.Entries++
		summary.Requests += entry.Requests
		summary.Cost += entry.Cost
		longest = max(longest, entry.Cost)
		if entry.Protocol == types.HeadlessProtocol.String() {
			headlessCost += entry.Cost
		}
	})
	if encodeErr != nil {
		return encodeErr
	}
	summary.EstimatedSeconds = r.estimateSeconds(summary.Requests, summary.Cost-headlessCost, headlessCost, longest)
	if err := encoder.Encode(map[string]planSummary{"summary": summary}); err != nil {
		return err
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	r.Logger.Info().Msgf("Plan written to %s: %d template runs, up to %d requests, about %ds", r.options.PlanFile, summary.Entries, summary.Requests, summary.EstimatedSeconds)
	return nil
}

// estimateSeconds estimates the scan duration. Headless templates run in
// their own, smaller pool, so their cost is spread over it separately.
func (r *Runner) estimateSeconds(requests, cost, headlessCost, longest int) int {
	seconds := float64(longest) * httpRequestSeconds
	if r.options.RateLimit > 0 && r.options.RateLimitDuration > 0 {
		seconds = max(seconds, float64(requests)/(float64(r.options.RateLimit)/r.options.RateLimitDuration.Seconds()))
	}
	if slots := r.options.TemplateThreads * r.options.BulkSize; slots > 0 {
		seconds = max(seconds, float64(cost)*httpRequestSeconds/float64(slots))
	}
	if slots := r.options.HeadlessTemplateThreads * r.options.HeadlessBulkSize; slots > 0 {
		seconds = max(seconds, float64(headlessCost)*httpRequestSeconds/float64(slots))
	}
	return int(seconds + 0.5)
}
