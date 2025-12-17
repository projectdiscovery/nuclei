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
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	syncutil "github.com/projectdiscovery/utils/sync"
	urlutil "github.com/projectdiscovery/utils/url"
)

const preflightWorkers = 25

type filteringInputProvider struct {
	base      provider.InputProvider
	allowed   map[string]struct{}
	allowCnt  int64
	execID    string
}

func (f *filteringInputProvider) Count() int64 { return f.allowCnt }
func (f *filteringInputProvider) InputType() string { return f.base.InputType() }
func (f *filteringInputProvider) Close() { f.base.Close() }
func (f *filteringInputProvider) Set(executionId string, value string) { f.base.Set(executionId, value) }
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
		if _, ok := f.allowed[key]; !ok {
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

	portsFromTemplates := portsFromTemplates(finalTemplates)
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

	portsToScan := sliceutil.Dedupe(append(keysOf(portsFromTemplates), keysOf(portsFromInputs)...))
	portsToScan = filterValidPorts(portsToScan)
	sort.Strings(portsToScan)

	// If no ports were found, nothing to scan -> keep all.
	if len(portsToScan) == 0 {
		return nil
	}

	r.Logger.Info().Msgf("Running preflight portscan (workers=%d, ports=%d, targets=%d)", preflightWorkers, len(portsToScan), totalTargets.Load())

	swg, err := syncutil.New(syncutil.WithSize(preflightWorkers))
	if err != nil {
		return err
	}

	var allowedMu sync.Mutex
	allowed := make(map[string]struct{}, len(inputs))

	var dnsFail atomic.Int64
	var portFail atomic.Int64
	var kept atomic.Int64

	perPortOpen := make(map[string]int64)
	var perPortMu sync.Mutex

	for _, t := range inputs {
		swg.Add()
		go func(t preflightTarget) {
			defer swg.Done()
			ok, openPort, reason := r.preflightOne(dialers, t.raw, portsToScan)
			if ok {
				allowedMu.Lock()
				allowed[t.key] = struct{}{}
				allowedMu.Unlock()
				kept.Add(1)
				if openPort != "" {
					perPortMu.Lock()
					perPortOpen[openPort]++
					perPortMu.Unlock()
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

	// Apply filtering wrapper
	r.inputProvider = &filteringInputProvider{
		base:     r.inputProvider,
		allowed:  allowed,
		allowCnt: int64(len(allowed)),
		execID:   r.options.ExecutionId,
	}

	// Summary
	if !r.options.Silent {
		dropped := totalTargets.Load() - kept.Load()
		r.Logger.Info().Msgf("Preflight summary: total=%d kept=%d filtered_dns=%d filtered_ports=%d",
			totalTargets.Load(), kept.Load(), dnsFail.Load(), portFail.Load())
		r.Logger.Info().Msgf("Preflight targets: dropped=%d left=%d", dropped, kept.Load())
		if len(perPortOpen) > 0 {
			type kv struct {
				port  string
				count int64
			}
			kvs := make([]kv, 0, len(perPortOpen))
			for p, c := range perPortOpen {
				kvs = append(kvs, kv{port: p, count: c})
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

func (r *Runner) preflightOne(dialers *protocolstate.Dialers, raw string, ports []string) (ok bool, openPort string, reason preflightReason) {
	host, schemePort, hasSchemePort, err := hostForResolveAndScan(raw)
	if err != nil {
		// If parsing fails, treat as raw host and try anyway.
		host = raw
	}
	if host == "" {
		return false, "", preflightReasonDNS
	}

	// Resolve hostnames (if not an IP).
	if !iputil.IsIP(host) {
		dns, err := dialers.Fastdialer.GetDNSData(host)
		if err != nil || (len(dns.A) == 0 && len(dns.AAAA) == 0) {
			return false, "", preflightReasonDNS
		}
	}

	// If input explicitly implied a single default port (http/https without explicit port),
	// prioritize that port first.
	ordered := ports
	if hasSchemePort && schemePort != "" {
		ordered = append([]string{schemePort}, ports...)
		ordered = sliceutil.Dedupe(ordered)
	}

	timeout := time.Duration(r.options.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	for _, p := range ordered {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		conn, err := dialers.Fastdialer.Dial(ctx, "tcp", net.JoinHostPort(host, p))
		cancel()
		if err == nil {
			_ = conn.Close()
			return true, p, preflightReasonNone
		}
	}
	return false, "", preflightReasonPorts
}

func portsFromTemplates(tpls []*templates.Template) map[string]struct{} {
	out := map[string]struct{}{}
	for _, tpl := range tpls {
		// HTTP templates imply 80/443 for preflight.
		if len(tpl.RequestsHTTP) > 0 || len(tpl.RequestsWithHTTP) > 0 || len(tpl.RequestsHeadless) > 0 {
			out["80"] = struct{}{}
			out["443"] = struct{}{}
		}
		// Network templates declare ports directly.
		for _, req := range tpl.RequestsNetwork {
			for _, p := range splitPorts(req.Port) {
				out[p] = struct{}{}
			}
		}
		for _, req := range tpl.RequestsWithTCP {
			for _, p := range splitPorts(req.Port) {
				out[p] = struct{}{}
			}
		}
		// Javascript templates may include args.Port (comma-separated).
		for _, req := range tpl.RequestsJavascript {
			for _, p := range extractPortsFromJSArgs(req.Args) {
				out[p] = struct{}{}
			}
		}
	}
	return out
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


