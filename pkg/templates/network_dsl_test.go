package templates_test

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/render"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/stretchr/testify/require"
)

func TestUnsignedTemplateNetworkDSLPolicy(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	var queries atomic.Int32
	server := &dns.Server{PacketConn: listener, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		queries.Add(1)
		response := new(dns.Msg).SetReply(r)
		response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("127.0.0.1")}}
		_ = w.WriteMsg(response)
	})}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { require.NoError(t, server.Shutdown()); require.NoError(t, <-done) })
	const source = `id: network-dsl-policy
info:
  name: Network DSL policy regression
  author: test
  severity: info
variables:
  resolved: '{{resolve("fixture.example")}}'
http:
  - method: GET
    path:
      - '{{BaseURL}}'
    matchers:
      - type: dsl
        dsl:
          - 'resolve("fixture.example") == "127.0.0.1"'
      - type: word
        words:
          - '{{resolve("fixture.example")}}'
    extractors:
      - type: dsl
        dsl:
          - 'resolve("fixture.example")'
`
	// Alternate restrictions so cached expressions cannot bypass the current policy.
	for _, item := range []struct {
		name                 string
		restricted, excluded bool
	}{
		{name: "allowed"},
		{name: "restricted", restricted: true},
		{name: "excluded without lna", excluded: true},
		{name: "excluded with lna", restricted: true, excluded: true},
		{name: "allowed again"},
		{name: "restricted again", restricted: true},
	} {
		t.Run(item.name, func(t *testing.T) {
			denied := item.restricted || item.excluded
			options := testutils.DefaultOptions.Copy()
			options.ExecutionId = t.Name()
			options.RestrictLocalNetworkAccess = item.restricted
			options.InternalResolversList = []string{listener.LocalAddr().String()}
			if item.excluded {
				options.ExcludeTargets = []string{"127.0.0.1"}
			}
			require.NoError(t, protocolinit.Init(options))
			t.Cleanup(func() { protocolinit.Close(options.ExecutionId) })
			executor := testutils.NewMockExecuterOptions(options, nil)
			t.Cleanup(executor.RateLimiter.Stop)
			before := queries.Load()
			template, err := templates.ParseTemplateFromReader(strings.NewReader(source), nil, executor)
			require.NoError(t, err)
			require.False(t, template.Verified)
			require.Equal(t, before, queries.Load(), "parsing must not perform network I/O")
			request := template.RequestsHTTP[0]
			data := map[string]interface{}{"body": "127.0.0.1", "template-id": template.ID}
			for _, matcher := range request.Matchers {
				matched, _ := request.Match(data, matcher)
				require.Equal(t, !denied, matched)
			}
			result := request.Extract(data, request.Extractors[0])
			if !denied {
				require.Contains(t, result, "127.0.0.1")
			} else {
				require.Empty(t, result)
			}
			values := template.Options.Variables.EvaluateScope(template.Options.NewVariablesScope()).Values
			if !denied {
				require.Equal(t, "127.0.0.1", values["resolved"])
			} else {
				require.Equal(t, `{{resolve("fixture.example")}}`, values["resolved"])
			}
			rendered, err := render.Render(render.Input{Text: `{{resolve("fixture.example")}}`, Options: options})
			if !denied {
				require.NoError(t, err)
				require.Equal(t, "127.0.0.1", rendered.Text)
			} else {
				require.ErrorContains(t, err, "network policy")
			}
			require.Greater(t, queries.Load(), before)
		})
	}
}
