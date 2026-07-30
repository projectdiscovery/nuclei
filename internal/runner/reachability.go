package runner

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/network"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

type probeResult int

const (
	portClosed  probeResult = iota // connection refused / host unreachable
	portOpen                        // connect succeeded
	portUnknown                     // timeout / filtered — treat as possibly open
)

const reachabilityProbeTimeout = 2 * time.Second

// strictProbeEnabled reports whether the lossless reachability prune
// applies to this run. It is limited to standard target inputs; request-shaped
// (DAST / multi-format) inputs are never pruned, because probing a request
// template as a live service is meaningless and could drop coverage.
func (r *Runner) strictProbeEnabled() bool {
	return r.options.StrictProbe &&
		r.inputProvider != nil &&
		r.inputProvider.InputType() != provider.MultiFormatInputProvider
}

// noHTTPServiceReachable reports whether NO target actually speaks HTTP(S).
//
// When it returns true, web templates (HTTP/headless/websocket) can be excluded
// losslessly: a port that does not serve HTTP has no HTTP application, so no
// HTTP template can produce a real finding there. Unlike a bare TCP-open check,
// this catches the open-but-non-HTTP case (e.g. redis on 6379): the port is
// open, but it is not an HTTP service, so HTTP templates are pure waste.
//
// It reuses nuclei's own httpx probe (the same one used for input routing), so
// the determination is consistent with the engine and respects the network
// policy (the probe dials only through the policy-configured httpx client).
// Conservative: an explicit http/https target, any scheme that responds, or the
// inability to probe safely all keep web templates in place.
func (r *Runner) noHTTPServiceReachable() bool {
	if r.inputProvider == nil {
		return false
	}
	dialers := protocolstate.GetDialersWithId(r.options.ExecutionId)
	if dialers == nil {
		return false // cannot probe within policy — keep web templates
	}
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
	client, err := httpx.New(&httpxOptions)
	if err != nil {
		return false // cannot probe — keep web templates
	}

	anyHTTP := false
	r.inputProvider.Iterate(func(mi *contextargs.MetaInput) bool {
		if strings.HasPrefix(mi.Input, "http://") || strings.HasPrefix(mi.Input, "https://") {
			anyHTTP = true
			return false
		}
		if utils.ProbeURL(mi.Input, client) != "" {
			anyHTTP = true
			return false
		}
		return true
	})
	return !anyHTTP
}

// pruneClosedTCPNetworkTemplates removes network(TCP) templates whose declared
// port(s) are definitively closed on every target. Provably lossless: such a
// template cannot connect anywhere, so it cannot produce a finding.
//
// Strictly gated to stay lossless:
//   - only applies when EVERY target is a bare host (no explicit port); an
//     explicit input port overrides the template port, so we skip those.
//   - only single-protocol, network-only templates (a mixed template could have
//     a reachable request in another protocol).
//   - only TCP: any udp:// address disqualifies the template (a TCP probe says
//     nothing about a UDP service — e.g. SNMP/mDNS).
//   - only concrete numeric ports; empty/dynamic/service-name ports are kept.
//   - prunes only when a port is CLOSED (refused); open or indeterminate keeps it.
func (r *Runner) pruneClosedTCPNetworkTemplates(in []*templates.Template) []*templates.Template {
	if r.inputProvider == nil || len(in) == 0 {
		return in
	}
	// Collect hosts; bail out (keep everything) if any input carries a port.
	var hosts []string
	bareOnly := true
	r.inputProvider.Iterate(func(mi *contextargs.MetaInput) bool {
		host, port := hostAndExplicitPort(mi.Input)
		if port != "" {
			bareOnly = false
			return false
		}
		if host != "" {
			hosts = append(hosts, host)
		}
		return true
	})
	if !bareOnly || len(hosts) == 0 {
		return in
	}
	hosts = sliceutil.Dedupe(hosts)

	// Identify prunable candidates and the ports to probe.
	candidatePorts := map[int][]string{}
	toProbe := map[string]struct{}{}
	for i, t := range in {
		ports, ok := tcpNetworkOnlyPorts(t)
		if !ok {
			continue
		}
		candidatePorts[i] = ports
		for _, p := range ports {
			toProbe[p] = struct{}{}
		}
	}
	if len(candidatePorts) == 0 {
		return in
	}

	// A port is "reachable" if open or indeterminate on ANY host.
	reachable := map[string]bool{}
	for p := range toProbe {
		for _, h := range hosts {
			res := r.probe(h, p)
			if res == portOpen || res == portUnknown {
				reachable[p] = true
				break
			}
		}
	}

	out := in[:0]
	pruned := 0
	for i, t := range in {
		if ports, ok := candidatePorts[i]; ok {
			anyReachable := false
			for _, p := range ports {
				if reachable[p] {
					anyReachable = true
					break
				}
			}
			if !anyReachable {
				pruned++
				continue
			}
		}
		out = append(out, t)
	}
	if pruned > 0 {
		gologger.Info().Msgf("reachability prune: excluded %d network(tcp) template[s] targeting only closed ports (lossless)", pruned)
	}
	return out
}

// tcpNetworkOnlyPorts returns the concrete numeric TCP ports of a single-protocol
// network template, or ok=false if the template is ineligible for port pruning.
func tcpNetworkOnlyPorts(t *templates.Template) ([]string, bool) {
	if len(t.RequestsNetwork)+len(t.RequestsWithTCP) == 0 {
		return nil, false
	}
	// must be network-only (no other protocol request could still be reachable)
	otherReqs := len(t.RequestsHTTP) + len(t.RequestsWithHTTP) + len(t.RequestsHeadless) +
		len(t.RequestsDNS) + len(t.RequestsFile) + len(t.RequestsSSL) +
		len(t.RequestsCode) + len(t.RequestsJavascript) + len(t.Workflows)
	if otherReqs > 0 {
		return nil, false
	}
	reqs := make([]*network.Request, 0, len(t.RequestsNetwork)+len(t.RequestsWithTCP))
	reqs = append(reqs, t.RequestsNetwork...)
	reqs = append(reqs, t.RequestsWithTCP...)

	var ports []string
	for _, req := range reqs {
		for _, addr := range req.Address {
			if strings.Contains(strings.ToLower(addr), "udp://") {
				return nil, false // UDP: a TCP probe cannot prove unreachability
			}
		}
		pp := splitPorts(req.Port)
		if len(pp) == 0 {
			return nil, false // empty/dynamic port (uses input port) — keep
		}
		for _, p := range pp {
			if !isNumericPort(p) {
				return nil, false // service name or template var — keep
			}
			ports = append(ports, p)
		}
	}
	if len(ports) == 0 {
		return nil, false
	}
	return sliceutil.Dedupe(ports), true
}

func isNumericPort(p string) bool {
	n, err := strconv.Atoi(p)
	return err == nil && n > 0 && n < 65536
}

// hostAndExplicitPort splits a target into host and explicit port (port empty if
// the target is a bare host).
func hostAndExplicitPort(input string) (string, string) {
	if strings.Contains(input, "://") {
		if u, err := url.Parse(input); err == nil && u.Hostname() != "" {
			return u.Hostname(), u.Port()
		}
	}
	if host, port, err := net.SplitHostPort(input); err == nil {
		return host, port
	}
	return input, ""
}

// probe classifies reachability of host:port WITHIN the scan's network policy.
// Security first: it never dials a target the policy forbids and never bypasses
// the sandbox — all probing goes through the execution's fastdialer, which
// enforces the same DenyList (‑lna, exclude-targets, private/metadata ranges,
// DNS-rebind protection) as the scan itself.
//
// It reconciles security with losslessness by mapping every uncertain case to
// portUnknown ("keep, don't dial"): a policy-denied host, a missing dialer, or a
// timeout all leave templates in place. Pruning happens only on a definitive,
// policy-permitted, refused connection.
func (r *Runner) probe(host, port string) probeResult {
	if !protocolstate.IsHostAllowed(r.options.ExecutionId, host) {
		// Policy denies this host: do not dial (security), do not prune (lossless).
		return portUnknown
	}
	dialers := protocolstate.GetDialersWithId(r.options.ExecutionId)
	if dialers == nil || dialers.Fastdialer == nil {
		// No policy-enforcing dialer available: never fall back to a raw dial.
		return portUnknown
	}
	return classifyDial(dialers.Fastdialer.Dial, net.JoinHostPort(host, port), reachabilityProbeTimeout)
}

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// classifyDial performs one connect via the supplied (policy-enforcing) dialer.
func classifyDial(dial dialFunc, addr string, timeout time.Duration) probeResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := dial(ctx, "tcp", addr)
	if err == nil {
		_ = conn.Close()
		return portOpen
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return portUnknown
	}
	return portClosed
}

