package http

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

func TestHTTPExtractMultipleReuse(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-http"
	request := &Request{
		ID: templateID,
		Raw: []string{
			`GET /robots.txt HTTP/1.1
			Host: {{Hostname}}
			User-Agent: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0
			Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
			Accept-Language: en-US,en;q=0.5
			`,

			`GET {{endpoint}} HTTP/1.1
			Host: {{Hostname}}
			User-Agent: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0
			Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
			Accept-Language: en-US,en;q=0.5
			`,
		},
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Part:  "body",
				Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
				Words: []string{"match /a", "match /b", "match /c"},
			}},
			Extractors: []*extractors.Extractor{{
				Part:     "body",
				Name:     "endpoint",
				Type:     extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor},
				Regex:    []string{"(?m)/([a-zA-Z0-9-_/\\\\]+)"},
				Internal: true,
			}},
		},
		IterateAll: true,
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			_, _ = w.Write([]byte(`User-agent: Googlebot
Disallow: /a
Disallow: /b
Disallow: /c`))
		default:
			_, _ = w.Write([]byte(fmt.Sprintf(`match %v`, r.URL.Path)))
		}
	}))
	defer ts.Close()

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})

	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile network request")

	var finalEvent *output.InternalWrappedEvent
	var matchCount int
	t.Run("test", func(t *testing.T) {
		metadata := make(output.InternalEvent)
		previous := make(output.InternalEvent)
		ctxArgs := contextargs.NewWithInput(ts.URL)
		err := request.ExecuteWithResults(ctxArgs, metadata, previous, func(event *output.InternalWrappedEvent) {
			if event.OperatorsResult != nil && event.OperatorsResult.Matched {
				matchCount++
			}
			finalEvent = event
		})
		require.Nil(t, err, "could not execute network request")
	})
	require.NotNil(t, finalEvent, "could not get event output from request")
	require.Equal(t, 3, matchCount, "could not get correct match count")
}

func TestDisableTE(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "http-disable-transfer-encoding"

	// in raw request format
	request := &Request{
		ID: templateID,
		Raw: []string{
			`POST / HTTP/1.1
			Host: {{Hostname}}
			User-Agent: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0
			Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
			Accept-Language: en-US,en;q=0.5

			login=1&username=admin&password=admin
			`,
		},
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Type:   matchers.MatcherTypeHolder{MatcherType: matchers.StatusMatcher},
				Status: []int{200},
			}},
		},
	}

	// in base request format
	request2 := &Request{
		ID:     templateID,
		Method: HTTPMethodTypeHolder{MethodType: HTTPPost},
		Path:   []string{"{{BaseURL}}"},
		Body:   "login=1&username=admin&password=admin",
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Type:   matchers.MatcherTypeHolder{MatcherType: matchers.StatusMatcher},
				Status: []int{200},
			}},
		},
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TransferEncoding) > 0 || r.ContentLength <= 0 {
			t.Error("Transfer-Encoding header should not be set")
		}
	}))
	defer ts.Close()

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})

	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile http raw request")

	err = request2.Compile(executerOpts)
	require.Nil(t, err, "could not compile http base request")

	var finalEvent *output.InternalWrappedEvent
	var matchCount int
	t.Run("test", func(t *testing.T) {
		metadata := make(output.InternalEvent)
		previous := make(output.InternalEvent)
		ctxArgs := contextargs.NewWithInput(ts.URL)
		err := request.ExecuteWithResults(ctxArgs, metadata, previous, func(event *output.InternalWrappedEvent) {
			if event.OperatorsResult != nil && event.OperatorsResult.Matched {
				matchCount++
			}
			finalEvent = event
		})
		require.Nil(t, err, "could not execute network request")
	})

	t.Run("test2", func(t *testing.T) {
		metadata := make(output.InternalEvent)
		previous := make(output.InternalEvent)
		ctxArgs := contextargs.NewWithInput(ts.URL)
		err := request2.ExecuteWithResults(ctxArgs, metadata, previous, func(event *output.InternalWrappedEvent) {
			if event.OperatorsResult != nil && event.OperatorsResult.Matched {
				matchCount++
			}
			finalEvent = event
		})
		require.Nil(t, err, "could not execute network request")
	})

	require.NotNil(t, finalEvent, "could not get event output from request")
	require.Equal(t, 2, matchCount, "could not get correct match count")
}
