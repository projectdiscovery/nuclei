package dsl

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/govaluate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/proxy"
)

func networkTestDNS(t *testing.T, address string) (string, *atomic.Int32) {
	t.Helper()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	queries := new(atomic.Int32)
	server := &dns.Server{PacketConn: listener, Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		queries.Add(1)
		response := new(dns.Msg).SetReply(request)
		for _, question := range request.Question {
			if question.Qtype == dns.TypeA {
				response.Answer = append(response.Answer, &dns.A{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP(address)})
			}
		}
		_ = writer.WriteMsg(response)
	})}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { require.NoError(t, server.Shutdown()); require.NoError(t, <-done) })
	return listener.LocalAddr().String(), queries
}

func networkTestOptions(t *testing.T, options *types.Options) *types.Options {
	t.Helper()
	if options.ExecutionId == "" {
		options.ExecutionId = t.Name()
	}
	require.NoError(t, protocolstate.Init(options))
	t.Cleanup(func() { protocolstate.Close(options.ExecutionId) })
	return options
}

func evalNetworkTest(t *testing.T, source string, options *types.Options) (interface{}, error) {
	t.Helper()
	expression, err := govaluate.NewEvaluableExpressionWithFunctions(source, HelperFunctions)
	require.NoError(t, err)
	return EvalWithOptions(expression, nil, options)
}

func TestNetworkHelpersRequireInitializedScan(t *testing.T) {
	for _, restricted := range []bool{false, true} {
		t.Run(fmt.Sprint(restricted), func(t *testing.T) {
			options := &types.Options{ExecutionId: t.Name(), RestrictLocalNetworkAccess: restricted}
			for _, expression := range []string{`resolve("example.com")`, `jarm("8.8.8.8:443")`, `public_ip()`, `publicip()`} {
				_, err := evalNetworkTest(t, expression, options)
				require.ErrorContains(t, err, "initialized scan dialers")
			}
		})
	}
}

func TestResolveNetworkPolicy(t *testing.T) {
	for _, item := range []struct {
		name, address, exclude string
		restricted, wantError  bool
	}{
		{name: "public without lna", address: "8.8.8.8"},
		{name: "public with lna", address: "8.8.8.8", restricted: true},
		{name: "private without lna", address: "127.0.0.1"},
		{name: "private with lna", address: "127.0.0.1", restricted: true, wantError: true},
		{name: "excluded address", address: "8.8.8.8", exclude: "8.8.8.8", wantError: true},
		{name: "excluded CIDR", address: "8.8.8.8", exclude: "8.8.8.0/24", wantError: true},
		{name: "excluded hostname", address: "8.8.8.8", exclude: "fixture.example", wantError: true},
		{name: "excluded with lna", address: "8.8.8.8", exclude: "8.8.8.0/24", restricted: true, wantError: true},
	} {
		t.Run(item.name, func(t *testing.T) {
			resolver, queries := networkTestDNS(t, item.address)
			options := &types.Options{RestrictLocalNetworkAccess: item.restricted, InternalResolversList: []string{resolver}}
			if item.exclude != "" {
				options.ExcludeTargets = []string{item.exclude}
			}
			networkTestOptions(t, options)
			result, err := evalNetworkTest(t, `resolve("fixture.example.")`, options)
			if item.wantError {
				require.ErrorContains(t, err, "network policy")
			} else {
				require.NoError(t, err)
				require.Equal(t, item.address, result)
			}
			if item.exclude == "fixture.example" {
				require.Zero(t, queries.Load())
			} else {
				require.Positive(t, queries.Load())
			}
		})
	}
}

func TestJARMNetworkPolicy(t *testing.T) {
	for _, target := range []string{"127.0.0.1:443", "[::1]:443", "[::ffff:127.0.0.1]:443", "8.8.8.8:443", "fixture.example:443"} {
		t.Run(target, func(t *testing.T) {
			resolver, _ := networkTestDNS(t, "127.0.0.1")
			options := networkTestOptions(t, &types.Options{RestrictLocalNetworkAccess: true, ExcludeTargets: []string{"8.8.8.0/24"}, InternalResolversList: []string{resolver}})
			_, err := evalNetworkTest(t, fmt.Sprintf("jarm(%q)", target), options)
			if target == "fixture.example:443" {
				require.ErrorIs(t, err, fastdialer.NoAddressAllowedError)
			} else {
				require.ErrorContains(t, err, "network policy")
			}
		})
	}
}

func TestJARMLocalNetworkMakesNoConnections(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var accepts atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	options := networkTestOptions(t, &types.Options{RestrictLocalNetworkAccess: true})
	_, err = evalNetworkTest(t, fmt.Sprintf("jarm(%q)", listener.Addr().String()), options)
	require.ErrorContains(t, err, "network policy")
	require.NoError(t, listener.Close())
	<-done
	require.Zero(t, accepts.Load())
}

type jarmTestProxy struct {
	calls atomic.Int32
	wg    sync.WaitGroup
}

func (p *jarmTestProxy) Dial(network, address string) (net.Conn, error) {
	p.calls.Add(1)
	client, server := net.Pipe()
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer func() { _ = server.Close() }()
		_ = server.SetDeadline(time.Now().Add(time.Second))
		buffer := make([]byte, 4096)
		_, _ = server.Read(buffer)
	}()
	return client, nil
}

func networkTestProxyDialer(t *testing.T, options *types.Options) *jarmTestProxy {
	t.Helper()
	state := protocolstate.GetDialersWithId(options.ExecutionId)
	controlledProxy := &jarmTestProxy{}
	var proxyDialer proxy.Dialer = controlledProxy
	dialerOptions := fastdialer.DefaultOptions
	dialerOptions.ResolversFile = false
	if len(options.InternalResolversList) > 0 {
		dialerOptions.BaseResolvers = options.InternalResolversList
	}
	dialerOptions.NetworkPolicy = state.NetworkPolicy
	dialerOptions.ProxyDialer = &proxyDialer
	controlledDialer, err := fastdialer.NewDialer(dialerOptions)
	require.NoError(t, err)
	state.Fastdialer.Close()
	state.Fastdialer = controlledDialer
	t.Cleanup(controlledProxy.wg.Wait)
	return controlledProxy
}

func TestJARMAllowedUsesScanDialer(t *testing.T) {
	for _, item := range []struct {
		name, address, exclude string
		restricted, denied     bool
	}{
		{name: "public without lna", address: "8.8.8.8"},
		{name: "local without lna", address: "127.0.0.1"},
		{name: "public with lna", address: "8.8.8.8", restricted: true},
		{name: "local with lna", address: "127.0.0.1", restricted: true, denied: true},
		{name: "excluded IP without lna", address: "8.8.8.8", exclude: "8.8.8.8", denied: true},
		{name: "excluded CIDR without lna", address: "8.8.8.8", exclude: "8.8.8.0/24", denied: true},
		{name: "excluded with lna", address: "8.8.8.8", exclude: "8.8.8.8", restricted: true, denied: true},
	} {
		t.Run(item.name, func(t *testing.T) {
			options := &types.Options{RestrictLocalNetworkAccess: item.restricted}
			if item.exclude != "" {
				options.ExcludeTargets = []string{item.exclude}
			}
			networkTestOptions(t, options)
			controlledProxy := networkTestProxyDialer(t, options)
			result, err := evalNetworkTest(t, fmt.Sprintf("jarm(%q)", net.JoinHostPort(item.address, "443")), options)
			controlledProxy.wg.Wait()
			if item.denied {
				require.ErrorContains(t, err, "network policy")
				require.Zero(t, controlledProxy.calls.Load())
			} else {
				require.NoError(t, err)
				require.Len(t, result, 62)
				require.EqualValues(t, 10, controlledProxy.calls.Load())
			}
		})
	}
}

func TestNetworkHelpersHonorExclusionsWithoutLNA(t *testing.T) {
	options := networkTestOptions(t, &types.Options{ExcludeTargets: []string{"blocked.example", "checkip.amazonaws.com"}})
	for _, source := range []string{`resolve("blocked.example")`, `jarm("blocked.example:443")`, `public_ip()`, `publicip()`} {
		t.Run(source, func(t *testing.T) {
			_, err := evalNetworkTest(t, source, options)
			require.ErrorContains(t, err, "network policy")
		})
	}
}

func TestNetworkHelperHostnameExclusions(t *testing.T) {
	for _, item := range []struct{ host, exclude string }{
		{"BLOCKED.EXAMPLE", "blocked.example"},
		{"blocked.example.", "BLOCKED.EXAMPLE"},
		{"bücher.example", "xn--bcher-kva.example"},
		{"xn--bcher-kva.example", "bücher.example"},
		{"sub.xn--bcher-kva.example", "bücher.example"},
		{"BÜCHER.EXAMPLE.", "bücher.example"},
		{"BLOCKED.EXAMPLE", `^blocked\.example$`},
		{"BLOCKED.EXAMPLE", `^BLOCKED\.EXAMPLE$`},
		{`bl\111cked.example`, "blocked.example"},
		{`\098locked.example`, "blocked.example"},
		{`\066LOCKED.EXAMPLE`, "blocked.example"},
		{`bl\ocked.example`, "blocked.example"},
		{"blocked.example.", `^blocked\.example\.$`},
	} {
		for _, restricted := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%s/lna-%t", item.host, item.exclude, restricted), func(t *testing.T) {
				resolver, queries := networkTestDNS(t, "8.8.8.8")
				options := networkTestOptions(t, &types.Options{RestrictLocalNetworkAccess: restricted, ExcludeTargets: []string{item.exclude}, InternalResolversList: []string{resolver}})
				controlledProxy := networkTestProxyDialer(t, options)
				for _, expression := range []string{fmt.Sprintf("resolve(%q)", item.host), fmt.Sprintf("jarm(%q)", net.JoinHostPort(item.host, "443"))} {
					t.Run(expression, func(t *testing.T) {
						_, err := evalNetworkTest(t, expression, options)
						controlledProxy.wg.Wait()
						require.ErrorContains(t, err, "network policy")
						require.Zero(t, queries.Load(), "excluded host caused a DNS query")
						require.Zero(t, controlledProxy.calls.Load(), "excluded host reached the proxy dialer")
					})
				}
			})
		}
	}
}

func TestPublicIPNetworkPolicy(t *testing.T) {
	for _, item := range []struct{ name, address, exclude string }{
		{"hostname", "8.8.8.8", "checkip.amazonaws.com"},
		{"uppercase hostname", "8.8.8.8", "CHECKIP.AMAZONAWS.COM"},
		{"IP", "8.8.8.8", "8.8.8.8"},
		{"CIDR", "8.8.8.8", "8.8.8.0/24"},
		{"private DNS answer", "127.0.0.1", ""},
	} {
		t.Run(item.name, func(t *testing.T) {
			resolver, _ := networkTestDNS(t, item.address)
			options := &types.Options{RestrictLocalNetworkAccess: true, InternalResolversList: []string{resolver}}
			if item.exclude != "" {
				options.ExcludeTargets = []string{item.exclude}
			}
			networkTestOptions(t, options)
			for _, source := range []string{`public_ip()`, `publicip()`} {
				_, err := evalNetworkTest(t, source, options)
				if item.name == "hostname" || item.name == "uppercase hostname" {
					require.ErrorContains(t, err, "network policy")
				} else {
					require.ErrorIs(t, err, fastdialer.NoAddressAllowedError)
				}
			}
		})
	}
}

func TestNetworkHelperConcurrentScanIsolation(t *testing.T) {
	allowed := networkTestOptions(t, &types.Options{ExecutionId: t.Name() + "/allowed"})
	denied := networkTestOptions(t, &types.Options{ExecutionId: t.Name() + "/restricted", RestrictLocalNetworkAccess: true})
	excluded := networkTestOptions(t, &types.Options{ExecutionId: t.Name() + "/excluded", ExcludeTargets: []string{"127.0.0.1"}})
	allowedProxy := networkTestProxyDialer(t, allowed)
	deniedProxy := networkTestProxyDialer(t, denied)
	excludedProxy := networkTestProxyDialer(t, excluded)
	expression, err := govaluate.NewEvaluableExpressionWithFunctions(`jarm("127.0.0.1:443")`, HelperFunctions)
	require.NoError(t, err)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(3)
		go func() {
			defer wg.Done()
			result, err := EvalWithOptions(expression, nil, allowed)
			if err != nil || result != strings.Repeat("0", 62) {
				t.Errorf("allowed scan: result=%v error=%v", result, err)
			}
		}()
		for _, options := range []*types.Options{denied, excluded} {
			go func() {
				defer wg.Done()
				_, err := EvalWithOptions(expression, nil, options)
				if err == nil || !strings.Contains(err.Error(), "network policy") {
					t.Errorf("denied scan: expected network policy error, got %v", err)
				}
			}()
		}
	}
	wg.Wait()
	allowedProxy.wg.Wait()
	require.EqualValues(t, 80, allowedProxy.calls.Load())
	require.Zero(t, deniedProxy.calls.Load())
	require.Zero(t, excludedProxy.calls.Load())
	// An options copy cannot bypass the policy of the initialized scan.
	forged := denied.Copy()
	forged.RestrictLocalNetworkAccess = false
	_, err = EvalWithOptions(expression, nil, forged)
	require.ErrorContains(t, err, "network policy")
	require.Zero(t, deniedProxy.calls.Load())
}
