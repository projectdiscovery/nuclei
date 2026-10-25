package dsl

import (
	"context"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	gojarm "github.com/hdm/jarm-go"
	"github.com/miekg/dns"
	"github.com/projectdiscovery/dsl"
	"github.com/projectdiscovery/govaluate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/retryabledns"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"golang.org/x/net/idna"
)

// EvalWithOptions evaluates an expression with the current scan's network policy.
// Cached expressions remain context-free; scan authority is never stored in them.
func EvalWithOptions(expression *govaluate.EvaluableExpression, values map[string]interface{}, options *types.Options) (interface{}, error) {
	if options == nil || !hasNetworkHelper(expression.String()) {
		return expression.Evaluate(values)
	}

	functions := maps.Clone(HelperFunctions)
	functions["resolve"] = func(args ...interface{}) (interface{}, error) { return resolve(options, args...) }
	functions["public_ip"] = func(args ...interface{}) (interface{}, error) { return publicIP(options, args...) }
	functions["publicip"] = functions["public_ip"]
	functions["jarm"] = func(args ...interface{}) (interface{}, error) { return jarm(options, args...) }

	bound, err := govaluate.NewEvaluableExpressionWithFunctions(expression.String(), functions)
	if err != nil {
		return nil, err
	}

	return bound.Evaluate(values)
}

// networkHelperCall matches a helper invocation, not a substring in another
// identifier or a quoted string. The global registry still denies every
// network helper, so an unrecognized spelling cannot bypass the gate.
var networkHelperCall = regexp.MustCompile(`\b(?:public_ip|publicip|resolve|jarm)\s*\(`)

func hasNetworkHelper(expression string) bool {
	return networkHelperCall.MatchString(stripQuotedStrings(expression))
}

func stripQuotedStrings(expression string) string {
	var builder strings.Builder
	builder.Grow(len(expression))

	for i := 0; i < len(expression); {
		char := expression[i]
		if char != '\'' && char != '"' {
			builder.WriteByte(char)
			i++
			continue
		}

		quote := char
		i++
		for i < len(expression) {
			if expression[i] == '\\' {
				i += 2
				continue
			}
			if expression[i] == quote {
				i++
				break
			}
			i++
		}
	}

	return builder.String()
}

func networkDialers(options *types.Options) (*protocolstate.Dialers, error) {
	if options == nil {
		return nil, ErrNetworkHelpersDisabled
	}

	state := protocolstate.GetDialersWithId(options.ExecutionId)
	if state == nil || state.Fastdialer == nil || state.NetworkPolicy == nil {
		return nil, fmt.Errorf("network DSL helpers require initialized scan dialers")
	}

	return state, nil
}

func canonicalNetworkHost(host string) (string, error) {
	if strings.Contains(host, `\`) {
		// Decode DNS presentation escapes before checking the host policy, using
		// the same wire representation as the resolver. Preserve escaped label dots.
		var wire [255]byte

		n, err := dns.PackDomainName(dns.Fqdn(host), wire[:], 0, nil, false)
		if err != nil {
			return "", err
		}

		host, _, err = dns.UnpackDomainName(wire[:n], 0)
		if err != nil {
			return "", err
		}
	}

	host = strings.TrimSuffix(host, ".")
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}

	// Match the dialer's IDNA conversion without rejecting DNS service labels.
	return idna.ToASCII(strings.ToLower(host))
}

func networkHost(state *protocolstate.Dialers, host string) (string, error) {
	canonical, err := canonicalNetworkHost(host)
	if err != nil {
		return "", fmt.Errorf("normalize network DSL host %q: %w", host, err)
	}

	allowed := state.NetworkPolicy.Validate(host) &&
		state.NetworkPolicy.Validate(strings.TrimSuffix(host, ".")) &&
		state.NetworkPolicy.Validate(canonical)

	// Also canonicalize plain hostname exclusions. Keep explicit regex rules
	// intact and check them against both the original and canonical host above.
	for excluded := range state.NetworkPolicy.DenyRules {
		if !allowed {
			break
		}

		if strings.ContainsAny(excluded, `\^$*+?()[]{}|`) {
			continue
		}

		normalized, err := canonicalNetworkHost(excluded)
		if err != nil {
			return "", fmt.Errorf("normalize network DSL exclusion %q: %w", excluded, err)
		}

		if normalized == excluded {
			continue
		}

		matched, err := regexp.MatchString(normalized, canonical)
		if err != nil {
			return "", fmt.Errorf("match network DSL exclusion %q: %w", excluded, err)
		}

		allowed = !matched
	}

	if !allowed {
		return "", fmt.Errorf("host %s denied by network policy", host)
	}

	return canonical, nil
}

func dialNetwork(ctx context.Context, state *protocolstate.Dialers, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	host, err = networkHost(state, host)
	if err != nil {
		return nil, err
	}

	// The dialer checks resolved IPs, including connections made through a proxy.
	return state.Fastdialer.Dial(ctx, network, net.JoinHostPort(host, port))
}

func resolve(options *types.Options, args ...interface{}) (interface{}, error) {
	argCount := len(args)
	if argCount == 0 || argCount > 2 {
		return nil, dsl.ErrInvalidDslFunction
	}

	format := "4"

	var dnsType uint16

	if len(args) > 1 {
		format = strings.ToLower(types.ToString(args[1]))
	}

	switch format {
	case "4", "a":
		dnsType = dns.TypeA
	case "6", "aaaa":
		dnsType = dns.TypeAAAA
	case "cname":
		dnsType = dns.TypeCNAME
	case "ns":
		dnsType = dns.TypeNS
	case "txt":
		dnsType = dns.TypeTXT
	case "srv":
		dnsType = dns.TypeSRV
	case "ptr":
		dnsType = dns.TypePTR
	case "mx":
		dnsType = dns.TypeMX
	case "soa":
		dnsType = dns.TypeSOA
	case "caa":
		dnsType = dns.TypeCAA
	default:
		return nil, fmt.Errorf("invalid dns type")
	}

	state, err := networkDialers(options)
	if err != nil {
		return nil, err
	}

	host, err := networkHost(state, types.ToString(args[0]))
	if err != nil {
		return nil, fmt.Errorf("resolve: %w", err)
	}

	dnsOptions := retryabledns.DefaultOptions
	if len(options.InternalResolversList) > 0 {
		dnsOptions.BaseResolvers = options.InternalResolversList
	}
	dnsOptions.Proxy = options.AliveSocksProxy

	dnsClient, err := retryabledns.NewWithOptions(dnsOptions)
	if err != nil {
		return nil, err
	}
	defer dnsClient.Close()

	// query
	rawResp, err := dnsClient.Query(host, dnsType)
	if err != nil {
		return nil, err
	}

	// A DNS answer must not reveal addresses that the scan excludes.
	for _, addresses := range [][]string{rawResp.A, rawResp.AAAA} {
		for _, address := range addresses {
			if !state.NetworkPolicy.Validate(address) {
				return nil, fmt.Errorf("resolve: address %s denied by network policy", address)
			}
		}
	}

	dnsValues := map[uint16][]string{
		dns.TypeA:     rawResp.A,
		dns.TypeAAAA:  rawResp.AAAA,
		dns.TypeCNAME: rawResp.CNAME,
		dns.TypeNS:    rawResp.NS,
		dns.TypeTXT:   rawResp.TXT,
		dns.TypeSRV:   rawResp.SRV,
		dns.TypePTR:   rawResp.PTR,
		dns.TypeMX:    rawResp.MX,
		dns.TypeCAA:   rawResp.CAA,
		dns.TypeSOA:   rawResp.GetSOARecords(),
	}

	if values, ok := dnsValues[dnsType]; ok {
		firstFound, found := sliceutil.FirstNonZero(values)
		if found {
			return firstFound, nil
		}
	}

	return "", fmt.Errorf("no records found")
}

func publicIP(options *types.Options, args ...interface{}) (interface{}, error) {
	if len(args) != 0 {
		return nil, dsl.ErrInvalidDslFunction
	}

	state, err := networkDialers(options)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialNetwork(ctx, state, network, address)
	}}
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}

	response, err := client.Get("https://checkip.amazonaws.com/")
	if err != nil {
		return nil, fmt.Errorf("public_ip: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("public_ip: unexpected HTTP status %s", response.Status)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil {
		return nil, fmt.Errorf("public_ip: read response: %w", err)
	}

	address := strings.TrimSpace(string(body))
	if net.ParseIP(address) == nil {
		return nil, fmt.Errorf("public_ip: service returned an invalid IP address")
	}

	return address, nil
}

func jarm(options *types.Options, args ...interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, dsl.ErrInvalidDslFunction
	}

	target, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("jarm: target must be a host:port string")
	}

	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("jarm: %w", err)
	}

	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("jarm: invalid port %q", portText)
	}

	state, err := networkDialers(options)
	if err != nil {
		return nil, err
	}

	host, err = networkHost(state, host)
	if err != nil {
		return nil, fmt.Errorf("jarm: %w", err)
	}

	target = net.JoinHostPort(host, portText)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	probes := gojarm.GetProbes(host, port)
	results := make([]string, 0, len(probes))

	for _, probe := range probes {
		conn, err := dialNetwork(ctx, state, "tcp", target)
		if err != nil {
			return nil, fmt.Errorf("jarm: dial target: %w", err)
		}

		// Each probe uses a fresh TCP connection and the scan's dial-time policy.
		err = conn.SetDeadline(time.Now().Add(10 * time.Second))
		if err == nil {
			_, err = conn.Write(gojarm.BuildProbe(probe))
		}

		var answer string

		if err == nil {
			buffer := make([]byte, 1484)
			_, _ = conn.Read(buffer)
			answer, _ = gojarm.ParseServerHello(buffer, probe)
		}

		_ = conn.Close()

		results = append(results, answer)
	}

	return gojarm.RawHashToFuzzyHash(strings.Join(results, ",")), nil
}
