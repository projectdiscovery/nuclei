package dns

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns" //nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
)

func TestDNSExecuteWithResults(t *testing.T) {
	options := testutils.DefaultOptions

	recursion := true
	testutils.Init(options)
	templateID := "testing-dns"
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	request := &Request{
		RequestType: DNSRequestTypeHolder{DNSRequestType: A},
		Class:       "INET",
		Retries:     5,
		ID:          templateID,
		Recursion:   &recursion,
		Name:        "{{FQDN}}",
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Name:  "test",
				Part:  "raw",
				Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
				Words: []string{"8.8.8.8"},
			}},
			Extractors: []*extractors.Extractor{{
				Part:  "raw",
				Type:  extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor},
				Regex: []string{"[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+"},
			}},
		},
		options: executerOpts,
	}
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile dns request")

	var finalEvent *output.InternalWrappedEvent
	t.Run("domain-valid", func(t *testing.T) {
		metadata := make(output.InternalEvent)
		previous := make(output.InternalEvent)
		ctxArgs := contextargs.NewWithInput(context.Background(), "dns.google")
		err := request.ExecuteWithResults(ctxArgs, metadata, previous, func(event *output.InternalWrappedEvent) {
			finalEvent = event
		})
		require.Nil(t, err, "could not execute dns request")
	})
	require.NotNil(t, finalEvent, "could not get event output from request")
	require.Equal(t, 1, len(finalEvent.Results), "could not get correct number of results")
	require.Equal(t, "test", finalEvent.Results[0].MatcherName, "could not get correct matcher name of results")
	require.GreaterOrEqual(t, 2, len(finalEvent.Results[0].ExtractedResults), "could not get correct number of extracted results")
	require.Contains(t, finalEvent.Results[0].ExtractedResults, "8.8.8.8", "could not get correct extracted results")
	require.Contains(t, finalEvent.Results[0].ExtractedResults, "8.8.4.4", "could not get correct extracted results")
	finalEvent = nil
	// Note: changing url to domain is responsible at tmplexec package and is implemented there
}

// With -pc below 1 the worker pool must still be built, and one payload is
// sent at a time, so the server sees them in iterator order.
//
//nolint:exhaustruct,exhaustruct_v5,paralleltest // fixtures keep zero-value defaults; the test options are global
func TestDNSPayloadsRunWithPayloadConcurrencyBelowOne(t *testing.T) {
	for _, payloadConcurrency := range []int{0, -1} {
		t.Run(fmt.Sprintf("pc=%d", payloadConcurrency), func(t *testing.T) {
			listener, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
			require.NoError(t, err)

			// ExecuteWithResults returns after the last reply, so every name is queued by then.
			names := make(chan string, 8)
			started := make(chan struct{})
			server := &dns.Server{
				PacketConn: listener,
				Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
					names <- r.Question[0].Name

					_ = w.WriteMsg(new(dns.Msg).SetReply(r))
				}),
				NotifyStartedFunc: func() { close(started) },
			}

			t.Cleanup(func() { _ = server.Shutdown() })

			go func() { _ = server.ActivateAndServe() }()

			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("dns server did not start")
			}

			options := testutils.DefaultOptions.Copy()
			options.PayloadConcurrency = payloadConcurrency
			testutils.Init(options)
			t.Cleanup(func() { testutils.Cleanup(options) })

			recursion := false
			request := &Request{
				ID:          "dns-payloads",
				RequestType: DNSRequestTypeHolder{DNSRequestType: A},
				Class:       "INET",
				Retries:     1,
				Recursion:   &recursion,
				Name:        "{{word}}.{{FQDN}}",
				Resolvers:   []string{listener.LocalAddr().String()},
				Payloads:    map[string]any{"word": []string{"one", "two", "three"}},
			}
			executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "dns-payloads"})
			require.NoError(t, request.Compile(executerOpts))
			require.Equal(t, 1, request.Threads, "a -pc below 1 sends one payload at a time")

			input := contextargs.NewWithInput(t.Context(), "example.com")
			err = request.ExecuteWithResults(input, nil, nil, func(*output.InternalWrappedEvent) {})
			require.NoError(t, err)

			got := make([]string, 0, len(names))
			for len(names) > 0 {
				got = append(got, <-names)
			}

			require.Equal(t, []string{"one.example.com.", "two.example.com.", "three.example.com."}, got)
		})
	}
}
