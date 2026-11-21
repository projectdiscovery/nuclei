package whois

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
)

func TestWhoisPreservesRegistrarWhoisServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/domain/example.com", r.URL.Path)
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = fmt.Fprint(w, `{"objectClassName":"domain","ldhName":"example.com","port43":"whois.example.com"}`)
	}))
	t.Cleanup(server.Close)

	_, event, _ := runWhoisDurationRequest(t, "example.com", server.URL)
	require.Equal(t, "whois.example.com", event["registrar whois server"])
	var response struct {
		Data            map[string][]string
		KeyDisplayOrder []string
	}
	require.NoError(t, json.Unmarshal([]byte(event["response"].(string)), &response))
	require.Equal(t, []string{"whois.example.com"}, response.Data["Registrar WHOIS Server"])
	require.Contains(t, response.KeyDisplayOrder, "Registrar WHOIS Server")
	require.NotContains(t, response.KeyDisplayOrder, "WHOIS Server")
}

func TestWhoisDuration(t *testing.T) {
	tests := []struct {
		name         string
		query        string
		expectedPath string
		response     string
	}{
		{
			name:         "domain",
			query:        "example.com",
			expectedPath: "/domain/example.com",
			response: `{
				"objectClassName": "domain",
				"ldhName": "example.com",
				"handle": "D123",
				"status": ["active"],
				"events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}]
			}`,
		},
		{
			name:         "ip",
			query:        "192.0.2.1",
			expectedPath: "/ip/192.0.2.1",
			response: `{
				"objectClassName": "ip network",
				"handle": "NET-EXAMPLE",
				"startAddress": "192.0.2.0",
				"endAddress": "192.0.2.255"
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, tt.expectedPath, r.URL.Path)
				w.Header().Set("Content-Type", "application/rdap+json")
				_, _ = fmt.Fprint(w, tt.response)
			}))
			defer server.Close()

			request, event, values := runWhoisDurationRequest(t, tt.query, server.URL)
			require.Equal(t, templateTypes.WHOISProtocol.String(), event["type"])
			require.Equal(t, tt.query, event["host"])
			require.NotEmpty(t, event["response"])
			requireWhoisDurationField(t, event, "duration")
			require.NotContains(t, event, "duration_1")
			require.Equal(t, event["duration"], values["duration-whois_duration"])
			extractor := &extractors.Extractor{
				Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.DSLExtractor},
				DSL:  []string{"duration"},
			}
			require.NoError(t, extractor.CompileExtractors())
			require.NotEmpty(t, request.Extract(event, extractor))
		})
	}
}

func TestWhoisDurationPartDefinitions(t *testing.T) {
	require.Contains(t, RequestPartDefinitions, "type")
	require.Contains(t, RequestPartDefinitions, "host")
	require.Contains(t, RequestPartDefinitions, "response")
	require.Contains(t, RequestPartDefinitions, "duration")
	require.NotContains(t, RequestPartDefinitions, "duration_ms")
	require.NotContains(t, RequestPartDefinitions, "duration_total")
	require.Equal(t, "whois-id", (&Request{ID: "whois-id"}).GetID())
}

func runWhoisDurationRequest(t *testing.T, query, server string) (*Request, output.InternalEvent, map[string]interface{}) {
	t.Helper()

	options := testutils.DefaultOptions
	testutils.Init(options)

	request := &Request{
		ID:     "duration-whois",
		Query:  query,
		Server: server,
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "testing-whois-duration",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	executerOpts.IsMultiProtocol = true
	require.NoError(t, request.Compile(executerOpts))

	var gotEvent output.InternalEvent
	ctxArgs := contextargs.NewWithInput(context.Background(), query)
	err := request.ExecuteWithResults(ctxArgs, nil, nil, func(event *output.InternalWrappedEvent) {
		gotEvent = event.InternalEvent
	})
	require.NoError(t, err)
	require.NotEmpty(t, gotEvent)
	return request, gotEvent, executerOpts.GetTemplateCtx(ctxArgs.MetaInput).GetAll()
}

func requireWhoisDurationField(t *testing.T, event output.InternalEvent, key string) {
	t.Helper()

	value, ok := event[key].(float64)
	require.Truef(t, ok, "expected %s to be a float64 duration", key)
	// Local mocks can finish within one timer tick (esp. on Windows), so 0s is valid.
	require.GreaterOrEqual(t, value, float64(0))
	require.Less(t, value, float64(60))
}
