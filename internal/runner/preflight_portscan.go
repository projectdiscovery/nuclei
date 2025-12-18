package runner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	inputtypes "github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/utils/errkit"
	iputil "github.com/projectdiscovery/utils/ip"
	mapsutil "github.com/projectdiscovery/utils/maps"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	syncutil "github.com/projectdiscovery/utils/sync"
	urlutil "github.com/projectdiscovery/utils/url"
)

const preflightWorkers = 100

// preflightDialTimeout is intentionally short: this is a coarse filter to skip
// obviously-dead targets before the real scan (which will use full timeouts).
const preflightDialTimeout = 750 * time.Millisecond

type filteringInputProvider struct {
	base     provider.InputProvider
	allowed  *mapsutil.SyncLockMap[string, struct{}]
	allowCnt int64
	execID   string
}

func (f *filteringInputProvider) Count() int64      { return f.allowCnt }
func (f *filteringInputProvider) InputType() string { return f.base.InputType() }
func (f *filteringInputProvider) Close()            { f.base.Close() }
func (f *filteringInputProvider) Set(executionId string, value string) {
	f.base.Set(executionId, value)
}
func (f *filteringInputProvider) SetWithProbe(executionId string, value string, probe inputtypes.InputLivenessProbe) error {
	return f.base.SetWithProbe(executionId, value, probe)
}
func (f *filteringInputProvider) SetWithExclusions(executionId string, value string) error {
	return f.base.SetWithExclusions(executionId, value)
}
func (f *filteringInputProvider) Iterate(callback func(value *contextargs.MetaInput) bool) {
	f.base.Iterate(func(mi *contextargs.MetaInput) bool {
		key, err := mi.MarshalString()
		if err != nil {
			return callback(mi)
		}
		if _, ok := f.allowed.Get(key); !ok {
			return true
		}
		return callback(mi)
	})
}

// preflightResolveAndPortScan resolves hostname targets and performs a TCP connect scan for ports
// required by loaded templates. Targets that are non-resolvable hostnames or have no relevant open
// ports are filtered out from the input provider.
func (r *Runner) preflightResolveAndPortScan(store *loader.Store) error {
	if r.inputProvider == nil {
		return nil
	}
	// MultiFormat inputs may represent complete requests; skip preflight for now.
	if r.inputProvider.InputType() == provider.MultiFormatInputProvider {
		return nil
	}

	finalTemplates := []*templates.Template{}
	finalTemplates = append(finalTemplates, store.Templates()...)
	finalTemplates = append(finalTemplates, store.Workflows()...)
	if len(finalTemplates) == 0 {
		return nil
	}

	dialers := protocolstate.GetDialersWithId(r.options.ExecutionId)
	if dialers == nil {
		return fmt.Errorf("dialers not initialized for %s", r.options.ExecutionId)
	}

	portsPopularity := portsPopularityFromTemplates(finalTemplates)
	// Also include ports explicitly present in input list (ip:port or URL with port),
	// so that a user-provided port isn't dropped even if templates didn't specify it.
	var inputs []preflightTarget
	portsFromInputs := map[string]struct{}{}
	var totalTargets atomic.Int64
	r.inputProvider.Iterate(func(mi *contextargs.MetaInput) bool {
		totalTargets.Add(1)
		key, err := mi.MarshalString()
		if err != nil {
			return true
		}
		inputs = append(inputs, preflightTarget{key: key, raw: mi.Input})
		extractPortsFromInput(portsFromInputs, mi.Input)
		return true
	})

	portsToScan := sliceutil.Dedupe(append(keysOfPopularity(portsPopularity), keysOf(portsFromInputs)...))
	portsToScan = filterValidPorts(portsToScan)
	// Sort by "likely-open" order (nmap-ish/common ports first), then numeric for determinism.
	likelyRank := likelyOpenPortRank()
	sort.Slice(portsToScan, func(i, j int) bool {
		pi, pj := portsToScan[i], portsToScan[j]
		ri, okRi := likelyRank[pi]
		rj, okRj := likelyRank[pj]
		// ranked ports first
		if okRi != okRj {
			return okRi
		}
		// among ranked ports, lower rank wins
		if okRi && okRj && ri != rj {
			return ri < rj
		}
		// numeric asc
		ni, _ := strconv.Atoi(pi)
		nj, _ := strconv.Atoi(pj)
		return ni < nj
	})

	// If no ports were found, nothing to scan -> keep all.
	if len(portsToScan) == 0 {
		return nil
	}

	r.Logger.Info().Msgf("Running preflight portscan (workers=%d, ports=%d, targets=%d)", preflightWorkers, len(portsToScan), totalTargets.Load())

	swg, err := syncutil.New(syncutil.WithSize(preflightWorkers))
	if err != nil {
		return err
	}

	// Resolve all targets (once) up-front so we can optionally run a single batched TCP dial scan.
	// Map original input key -> resolved IPs (deduped).
	// SyncLockMap requires comparable values; store resolved IPs as a comma-separated string.
	resolvedIPsByKey := mapsutil.NewSyncLockMap[string, string]()
	allIPsSet := mapsutil.NewSyncLockMap[string, struct{}]()
	var resolveProcessed atomic.Int64
	var resolveDNSFail atomic.Int64

	for _, t := range inputs {
		swg.Add()
		go func(t preflightTarget) {
			defer swg.Done()
			host, _, _, _ := hostForResolveAndScan(t.raw)
			if host == "" {
				resolveDNSFail.Add(1)
				resolveProcessed.Add(1)
				return
			}
			ips := []string{}
			if iputil.IsIP(host) {
				ips = append(ips, host)
			} else {
				dns, err := dialers.Fastdialer.GetDNSData(host)
				if err != nil || (len(dns.A) == 0 && len(dns.AAAA) == 0) {
					resolveDNSFail.Add(1)
					resolveProcessed.Add(1)
					return
				}
				ips = append(ips, dns.A...)
				ips = append(ips, dns.AAAA...)
			}
			ips = sliceutil.Dedupe(ips)
			if len(ips) == 0 {
				resolveDNSFail.Add(1)
				resolveProcessed.Add(1)
				return
			}

			// store
			// (small contention; acceptable at preflight scale)
			_ = resolvedIPsByKey.Set(t.key, strings.Join(ips, ","))
			for _, ip := range ips {
				_ = allIPsSet.Set(ip, struct{}{})
			}
			resolveProcessed.Add(1)
		}(t)
	}
	swg.Wait()

	// Prepare list of all IPs for scan.
	allIPsMap := allIPsSet.GetAll()
	allIPs := make([]string, 0, len(allIPsMap))
	for ip := range allIPsMap {
		allIPs = append(allIPs, ip)
	}
	sort.Strings(allIPs)

	// we do fast TCP dial scanning against resolved IPs.
	if !r.options.Silent {
		r.Logger.Info().Msgf("Preflight resolution: total=%d resolvable=%d unresolvable=%d", totalTargets.Load(), int64(len(resolvedIPsByKey.GetAll())), resolveDNSFail.Load())
	}

	allowed := mapsutil.NewSyncLockMap[string, struct{}]()

	var dnsFail atomic.Int64
	var portFail atomic.Int64
	var kept atomic.Int64
	var processed atomic.Int64

	perPortOpen := mapsutil.NewSyncLockMap[string, *atomic.Int64]()

	// Periodic progress logging
	// Always enabled unless running in silent mode.
	debugProgress := true
	stopProgress := make(chan struct{})
	if debugProgress && !r.options.Silent {
		start := time.Now()
		go func() {
			t := time.NewTicker(1 * time.Second)
			defer t.Stop()
			var lastProcessed int64
			for {
				select {
				case <-t.C:
					p := processed.Load()
					if p == lastProcessed {
						continue
					}
					lastProcessed = p
					total := totalTargets.Load()
					k := kept.Load()
					df := dnsFail.Load()
					pf := portFail.Load()
					dropped := p - k
					r.Logger.Info().Msgf("Preflight progress: %d/%d processed (kept=%d dropped=%d dns_fail=%d port_fail=%d elapsed=%s)",
						p, total, k, dropped, df, pf, time.Since(start).Truncate(time.Second))
				case <-stopProgress:
					return
				}
			}
		}()
	}

	for _, t := range inputs {
		swg.Add()
		go func(t preflightTarget) {
			defer swg.Done()
			ok, openPort, reason := r.preflightOneResolved(t.key, t.raw, portsToScan, resolvedIPsByKey, dialers)
			processed.Add(1)
			if ok {
				_ = allowed.Set(t.key, struct{}{})
				kept.Add(1)
				if openPort != "" {
					counter, _ := perPortOpen.Get(openPort)
					if counter == nil {
						counter = &atomic.Int64{}
						_ = perPortOpen.Set(openPort, counter)
					}
					counter.Add(1)
				}
				return
			}
			switch reason {
			case preflightReasonDNS:
				dnsFail.Add(1)
			case preflightReasonPorts:
				portFail.Add(1)
			}
		}(t)
	}
	swg.Wait()
	close(stopProgress)

	// Apply filtering wrapper
	allowedAll := allowed.GetAll()
	r.inputProvider = &filteringInputProvider{
		base:     r.inputProvider,
		allowed:  allowed,
		allowCnt: int64(len(allowedAll)),
		execID:   r.options.ExecutionId,
	}

	// Summary
	if !r.options.Silent {
		dropped := totalTargets.Load() - kept.Load()
		r.Logger.Info().Msgf("Preflight summary: total=%d kept=%d filtered_dns=%d filtered_ports=%d",
			totalTargets.Load(), kept.Load(), dnsFail.Load(), portFail.Load())
		r.Logger.Info().Msgf("Preflight targets: dropped=%d left=%d", dropped, kept.Load())
		perPortOpenAll := perPortOpen.GetAll()
		if len(perPortOpenAll) > 0 {
			type kv struct {
				port  string
				count int64
			}
			kvs := make([]kv, 0, len(perPortOpenAll))
			for p, c := range perPortOpenAll {
				if c == nil {
					continue
				}
				kvs = append(kvs, kv{port: p, count: c.Load()})
			}
			sort.Slice(kvs, func(i, j int) bool {
				if kvs[i].count == kvs[j].count {
					return kvs[i].port < kvs[j].port
				}
				return kvs[i].count > kvs[j].count
			})
			parts := make([]string, 0, len(kvs))
			for _, item := range kvs {
				parts = append(parts, fmt.Sprintf("%s=%d", item.port, item.count))
			}
			r.Logger.Info().Msgf("Preflight open-port distribution: %s", strings.Join(parts, " "))
		}
	}

	_ = gologger.DefaultLogger // ensure logger imported even when silent builds vary
	return nil
}

type preflightTarget struct {
	key string
	raw string
}

type preflightReason int

const (
	preflightReasonNone preflightReason = iota
	preflightReasonDNS
	preflightReasonPorts
)

func (r *Runner) preflightOneResolved(key string, raw string, ports []string, resolved *mapsutil.SyncLockMap[string, string], dialers *protocolstate.Dialers) (ok bool, openPort string, reason preflightReason) {
	resolvedIPsCSV, _ := resolved.Get(key)
	if resolvedIPsCSV == "" {
		return false, "", preflightReasonDNS
	}
	ips := strings.Split(resolvedIPsCSV, ",")

	// TCP dial scan using resolved IPs
	host, schemePort, hasSchemePort, _ := hostForResolveAndScan(raw)
	ordered := ports
	if hasSchemePort && schemePort != "" {
		ordered = append([]string{schemePort}, ports...)
		ordered = sliceutil.Dedupe(ordered)
	}

	timeout := preflightDialTimeout
	if r.options.Timeout > 0 {
		t := time.Duration(r.options.Timeout) * time.Second
		if t > 0 && t < timeout {
			timeout = t
		}
	}
	// Use net.Dialer directly for strict timeout enforcement.
	// We already resolved IPs, so we don't need fastdialer DNS behavior here.
	// This avoids rare cases where proxy dialers / custom dial stacks may not respect ctx cancellation promptly.
	d := &net.Dialer{Timeout: timeout}

	// Per-host parallelism: probe up to 3 ports concurrently, stop on first success.
	ctx, cancelAll := context.WithCancel(context.Background())
	defer cancelAll()

	type hit struct {
		port string
	}
	resultCh := make(chan hit, 1)
	portsCh := make(chan string)

	worker := func() {
		for p := range portsCh {
			// Stop quickly if someone already found an open port.
			select {
			case <-ctx.Done():
				return
			default:
			}

			for _, ip := range ips {
				_ = host // keep for debugging parity
				dctx, cancel := context.WithTimeout(ctx, timeout)
				conn, err := d.DialContext(dctx, "tcp", net.JoinHostPort(ip, p))
				cancel()
				if err == nil {
					_ = conn.Close()
					// Best-effort: first hit wins.
					select {
					case resultCh <- hit{port: p}:
						cancelAll()
					default:
					}
					return
				}
				// If ctx cancelled (other worker won), stop early.
				select {
				case <-ctx.Done():
					return
				default:
				}
			}
		}
	}

	var wg sync.WaitGroup
	workers := 3
	if len(ordered) < workers {
		workers = len(ordered)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker()
		}()
	}

	go func() {
		defer close(portsCh)
		for _, p := range ordered {
			select {
			case <-ctx.Done():
				return
			case portsCh <- p:
			}
		}
	}()

	// Wait for either a hit or all workers to finish.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case h := <-resultCh:
		<-done
		return true, h.port, preflightReasonNone
	case <-done:
		return false, "", preflightReasonPorts
	}
}

func portsPopularityFromTemplates(tpls []*templates.Template) map[string]int {
	out := map[string]int{}
	for _, tpl := range tpls {
		// HTTP templates imply 80/443 for preflight.
		if len(tpl.RequestsHTTP) > 0 || len(tpl.RequestsWithHTTP) > 0 || len(tpl.RequestsHeadless) > 0 {
			out["80"]++
			out["443"]++
		}
		// Network templates declare ports directly.
		for _, req := range tpl.RequestsNetwork {
			for _, p := range splitPorts(req.Port) {
				out[p]++
			}
		}
		for _, req := range tpl.RequestsWithTCP {
			for _, p := range splitPorts(req.Port) {
				out[p]++
			}
		}
		// Javascript templates may include args.Port (comma-separated).
		for _, req := range tpl.RequestsJavascript {
			for _, p := range extractPortsFromJSArgs(req.Args) {
				out[p]++
			}
		}
	}
	return out
}

func keysOfPopularity(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// likelyOpenPortRank returns a heuristic "most likely to be open" ranking for common TCP ports.
// This is intentionally static (fast + deterministic) and loosely aligns with what scanners like nmap
// tend to prioritize (common services first).
func likelyOpenPortRank() map[string]int {
	// Lower index = higher priority.
	// Keep this list small-ish but useful; anything not in here falls back to template popularity + numeric.
	common := []string{
		"80", "443",
		"22", "21", "23",
		"25", "110", "143", "465", "587", "993", "995",
		"53",
		"3389",
		"445", "139",
		"135",
		"3306", "5432", "1433", "1521",
		"6379", "27017",
		"9200", "9300",
		"8080", "8443", "8000", "8008", "8081", "8888",
		"9201",
		"161", "162",
		"389", "636",
		"5900",
		"11211",
		"69", "123",
		"1194",
		"500", "4500",
	}
	rank := make(map[string]int, len(common))
	for i, p := range common {
		// do not overwrite if duplicates
		if _, ok := rank[p]; !ok {
			rank[p] = i
		}
	}
	return rank
}

func extractPortsFromJSArgs(args map[string]interface{}) []string {
	if args == nil {
		return nil
	}
	for k, v := range args {
		if strings.EqualFold(k, "Port") {
			s := fmt.Sprint(v)
			return splitPorts(s)
		}
	}
	return nil
}

func splitPorts(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func extractPortsFromInput(dst map[string]struct{}, input string) {
	if dst == nil {
		return
	}
	in := strings.TrimSpace(input)
	if in == "" {
		return
	}
	low := strings.ToLower(in)
	if strings.HasPrefix(low, "http://") {
		dst["80"] = struct{}{}
	}
	if strings.HasPrefix(low, "https://") {
		dst["443"] = struct{}{}
	}
	// URL parsing (best effort)
	if u, err := urlutil.Parse(in); err == nil && u != nil {
		if p := u.Port(); p != "" {
			dst[p] = struct{}{}
		} else if u.Scheme == "http" {
			dst["80"] = struct{}{}
		} else if u.Scheme == "https" {
			dst["443"] = struct{}{}
		}
		return
	}
	// host:port
	_, p, err := net.SplitHostPort(in)
	if err == nil && p != "" {
		dst[p] = struct{}{}
	}
}

func hostForResolveAndScan(raw string) (host string, schemeDefaultPort string, hasSchemePort bool, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", false, errkit.New("empty input")
	}
	// If it looks like URL, parse and extract hostname.
	if stringsutil.ContainsAny(raw, "://") {
		u, perr := urlutil.ParseAbsoluteURL(raw, false)
		if perr == nil && u != nil {
			host = u.Hostname()
			if u.Port() != "" {
				return host, "", false, nil
			}
			switch strings.ToLower(u.Scheme) {
			case "http":
				return host, "80", true, nil
			case "https":
				return host, "443", true, nil
			}
			return host, "", false, nil
		}
	}
	// Try host:port form
	h, _, serr := net.SplitHostPort(raw)
	if serr == nil && h != "" {
		return h, "", false, nil
	}
	// Bare host/ip
	return raw, "", false, nil
}

func keysOf(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func filterValidPorts(ports []string) []string {
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		if p == "" {
			continue
		}
		// allow numeric only
		if !isNumeric(p) {
			continue
		}
		i, err := strconv.Atoi(p)
		if err != nil || i < 1 || i > 65535 {
			continue
		}
		out = append(out, p)
	}
	return sliceutil.Dedupe(out)
}

func isNumeric(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
