package runner

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/nuclei/v3/pkg/input"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	sliceutil "github.com/projectdiscovery/utils/slice"
	syncutil "github.com/projectdiscovery/utils/sync"
)

const hostGroupProbeWorkers = 100

// hostGroup is a set of targets that share the same open-port / HTTP signature.
// Used for savings estimates / logging; execution itself is a single spray pass
// with a per-(template,target) filter derived from the same probe data.
type hostGroup struct {
	key       string
	hosts     []*contextargs.MetaInput
	openPorts map[string]struct{}
	httpOK    bool
}

type hostProbeResult struct {
	input     *contextargs.MetaInput
	openPorts []string
	httpOK    bool
}

// hostReachabilityIndex maps each input to its probed reachability so the
// engine can skip impossible template×target pairs in a single Execute pass.
type hostReachabilityIndex struct {
	byInput map[string]hostReachability
}

type hostReachability struct {
	openPorts map[string]struct{}
	httpOK    bool
}

// Allow reports whether template may produce a finding on input (lossless).
func (idx *hostReachabilityIndex) Allow(t *templates.Template, mi *contextargs.MetaInput) bool {
	if idx == nil || t == nil || mi == nil {
		return true
	}
	h, ok := idx.byInput[mi.Input]
	if !ok {
		return true
	}
	return templateAllowedOnHost(t, h.httpOK, h.openPorts)
}

func templateAllowedOnHost(t *templates.Template, httpOK bool, openPorts map[string]struct{}) bool {
	if t.SelfContained || len(t.Workflows) > 0 || isUniversalTemplate(t) {
		return true
	}
	if isWebTemplate(t) {
		return httpOK
	}
	ports, ok := tcpNetworkOnlyPorts(t)
	if !ok {
		return true
	}
	for _, p := range ports {
		if _, open := openPorts[p]; open {
			return true
		}
	}
	return false
}

// estimateTemplateRequests mirrors core.getRequestCount for scheduling math.
func estimateTemplateRequests(tpls []*templates.Template) int {
	count := 0
	for _, t := range tpls {
		if len(t.Workflows) > 0 {
			continue
		}
		if t.TotalRequests > 0 {
			count += t.TotalRequests
			continue
		}
		count++
	}
	return count
}

func hostGroupKey(openPorts []string, httpOK bool) string {
	ports := append([]string(nil), openPorts...)
	sort.Strings(ports)
	http := "nohttp"
	if httpOK {
		http = "http"
	}
	if len(ports) == 0 {
		return http + "|-"
	}
	return http + "|" + strings.Join(ports, ",")
}

func isWebTemplate(t *templates.Template) bool {
	return len(t.RequestsHTTP)+len(t.RequestsWithHTTP)+len(t.RequestsHeadless)+len(t.RequestsWebsocket) > 0 &&
		len(t.RequestsNetwork)+len(t.RequestsWithTCP)+len(t.RequestsDNS)+len(t.RequestsFile)+
			len(t.RequestsSSL)+len(t.RequestsCode)+len(t.RequestsJavascript)+len(t.Workflows) == 0
}

func isUniversalTemplate(t *templates.Template) bool {
	if t.SelfContained || len(t.Workflows) > 0 {
		return true
	}
	if _, ok := tcpNetworkOnlyPorts(t); ok {
		return false
	}
	if isWebTemplate(t) {
		return false
	}
	return true
}

// templatesForHostGroup returns templates that can produce findings on this group.
func templatesForHostGroup(all []*templates.Template, g hostGroup) []*templates.Template {
	out := make([]*templates.Template, 0, len(all))
	for _, t := range all {
		if t.SelfContained || len(t.Workflows) > 0 || isUniversalTemplate(t) {
			continue
		}
		if templateAllowedOnHost(t, g.httpOK, g.openPorts) {
			out = append(out, t)
		}
	}
	return out
}

func partitionTemplates(all []*templates.Template) (web, network, universal, selfContained []*templates.Template) {
	for _, t := range all {
		switch {
		case t.SelfContained:
			selfContained = append(selfContained, t)
		case len(t.Workflows) > 0:
			universal = append(universal, t)
		case isWebTemplate(t):
			web = append(web, t)
		case isUniversalTemplate(t):
			universal = append(universal, t)
		default:
			network = append(network, t)
		}
	}
	return
}

// buildHostReachability probes each target once, then returns an index for
// single-pass filtering plus host groups for logging/estimates.
//
// HTTP reachability prefers the already-populated InputHelper.InputsHTTP map
// (from initializeTemplatesHTTPInput) so we do not re-run httpx.
// When probePorts is false, only explicit input ports are recorded (HTTP-only mode).
func (r *Runner) buildHostReachability(tpls []*templates.Template, httpHelper *input.Helper, probePorts bool) (*hostReachabilityIndex, []hostGroup, error) {
	if r.inputProvider == nil {
		return nil, nil, fmt.Errorf("no input provider")
	}

	var portsToProbe []string
	if probePorts {
		portsMap := portsPopularityFromTemplates(tpls)
		portsToProbe = make([]string, 0, len(portsMap))
		for p := range portsMap {
			if isNumericPort(p) {
				portsToProbe = append(portsToProbe, p)
			}
		}
		portsToProbe = sliceutil.Dedupe(portsToProbe)
		sort.Strings(portsToProbe)
	}

	var targets []*contextargs.MetaInput
	r.inputProvider.Iterate(func(mi *contextargs.MetaInput) bool {
		targets = append(targets, mi.Clone())
		return true
	})
	if len(targets) == 0 {
		return &hostReachabilityIndex{byInput: map[string]hostReachability{}}, nil, nil
	}

	// Only build an httpx client if we still need live HTTP probes.
	needLiveHTTPProbe := false
	for _, mi := range targets {
		if strings.HasPrefix(mi.Input, "http://") || strings.HasPrefix(mi.Input, "https://") {
			continue
		}
		if httpHelper != nil && httpHelper.InputsHTTP != nil {
			continue // already probed (hit or miss) during initializeTemplatesHTTPInput
		}
		needLiveHTTPProbe = true
		break
	}

	var httpClient *httpx.HTTPX
	if needLiveHTTPProbe {
		dialers := protocolstate.GetDialersWithId(r.options.ExecutionId)
		if dialers != nil {
			httpxOptions := httpx.DefaultOptions
			if r.options.AliveHttpProxy != "" {
				httpxOptions.Proxy = r.options.AliveHttpProxy
			} else if r.options.AliveSocksProxy != "" {
				httpxOptions.Proxy = r.options.AliveSocksProxy
			}
			httpxOptions.RetryMax = r.options.Retries
			if r.options.Timeout > 0 {
				httpxOptions.Timeout = time.Duration(r.options.Timeout) * time.Second
			}
			httpxOptions.NetworkPolicy = dialers.NetworkPolicy
			if c, err := httpx.New(&httpxOptions); err == nil {
				httpClient = c
			}
		}
	}

	workers := hostGroupProbeWorkers
	// Fan out one task per host:port so closed-port timeouts do not serialize per host.
	type probeJob struct {
		hostIdx int
		host    string
		port    string
	}
	var jobs []probeJob
	hostMeta := make([]struct {
		mi           *contextargs.MetaInput
		host         string
		explicitPort string
	}, len(targets))

	for i, mi := range targets {
		host, explicitPort := hostAndExplicitPort(mi.Target())
		if host == "" {
			host, explicitPort = hostAndExplicitPort(mi.Input)
		}
		hostMeta[i].mi = mi
		hostMeta[i].host = host
		hostMeta[i].explicitPort = explicitPort
		if !probePorts {
			continue
		}
		for _, p := range portsToProbe {
			if explicitPort != "" && p != explicitPort {
				continue
			}
			jobs = append(jobs, probeJob{hostIdx: i, host: host, port: p})
		}
	}

	if len(jobs) < workers {
		workers = len(jobs)
	}
	if workers < 1 {
		workers = 1
	}

	openByHost := make([]map[string]struct{}, len(targets))
	for i := range openByHost {
		openByHost[i] = map[string]struct{}{}
		if ep := hostMeta[i].explicitPort; ep != "" && isNumericPort(ep) {
			openByHost[i][ep] = struct{}{}
		}
	}

	if len(jobs) > 0 {
		swg, err := syncutil.New(syncutil.WithSize(workers))
		if err != nil {
			return nil, nil, err
		}
		var mu sync.Mutex
		for _, job := range jobs {
			swg.Add()
			go func(job probeJob) {
				defer swg.Done()
				switch r.probe(job.host, job.port) {
				case portOpen, portUnknown:
					mu.Lock()
					openByHost[job.hostIdx][job.port] = struct{}{}
					mu.Unlock()
				}
			}(job)
		}
		swg.Wait()
	}

	results := make([]hostProbeResult, len(targets))
	for i, meta := range hostMeta {
		open := openByHost[i]
		ports := make([]string, 0, len(open))
		for p := range open {
			ports = append(ports, p)
		}
		sort.Strings(ports)
		results[i] = hostProbeResult{
			input:     meta.mi,
			openPorts: ports,
			httpOK:    resolveHTTPReachability(meta.mi, open, httpHelper, httpClient),
		}
	}

	idx := &hostReachabilityIndex{byInput: make(map[string]hostReachability, len(results))}
	grouped := map[string]*hostGroup{}
	order := make([]string, 0)
	for _, res := range results {
		if res.input == nil {
			continue
		}
		portsSet := make(map[string]struct{}, len(res.openPorts))
		for _, p := range res.openPorts {
			portsSet[p] = struct{}{}
		}
		idx.byInput[res.input.Input] = hostReachability{
			openPorts: portsSet,
			httpOK:    res.httpOK,
		}

		key := hostGroupKey(res.openPorts, res.httpOK)
		g, ok := grouped[key]
		if !ok {
			g = &hostGroup{
				key:       key,
				openPorts: portsSet,
				httpOK:    res.httpOK,
			}
			grouped[key] = g
			order = append(order, key)
		}
		g.hosts = append(g.hosts, res.input)
	}

	out := make([]hostGroup, 0, len(order))
	for _, key := range order {
		out = append(out, *grouped[key])
	}
	return idx, out, nil
}

func resolveHTTPReachability(mi *contextargs.MetaInput, open map[string]struct{}, helper *input.Helper, client *httpx.HTTPX) bool {
	if mi == nil {
		return false
	}
	if strings.HasPrefix(mi.Input, "http://") || strings.HasPrefix(mi.Input, "https://") {
		return true
	}
	// Reuse httpx results from initializeTemplatesHTTPInput when available.
	if helper != nil && helper.InputsHTTP != nil {
		if probed, ok := helper.InputsHTTP.Get(mi.Input); ok && len(probed) > 0 {
			return true
		}
		// Map was built for all inputs: absence means not HTTP.
		return false
	}
	if client != nil {
		return utils.ProbeURL(mi.Input, client) != ""
	}
	if _, ok := open["80"]; ok {
		return true
	}
	if _, ok := open["443"]; ok {
		return true
	}
	return false
}

// estimateGroupedExecutions returns baseline and filtered template×host counts.
func estimateGroupedExecutions(all []*templates.Template, groups []hostGroup, hostCount int) (baseline, filtered int) {
	baseline = estimateTemplateRequests(all) * hostCount
	_, _, universal, selfContained := partitionTemplates(all)
	once := append([]*templates.Template{}, selfContained...)
	once = append(once, universal...)
	filtered = estimateTemplateRequests(once) * hostCount
	for _, g := range groups {
		filtered += estimateTemplateRequests(templatesForHostGroup(all, g)) * len(g.hosts)
	}
	return baseline, filtered
}

// countReachabilityStats returns concrete network template count and distinct numeric ports to probe.
func countReachabilityStats(tpls []*templates.Template) (concreteNetwork int, portsToProbe int) {
	ports := map[string]struct{}{}
	for _, t := range tpls {
		ps, ok := tcpNetworkOnlyPorts(t)
		if !ok {
			continue
		}
		concreteNetwork++
		for _, p := range ps {
			ports[p] = struct{}{}
		}
	}
	return concreteNetwork, len(ports)
}
