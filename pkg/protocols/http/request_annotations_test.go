package http

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	commoninteractsh "github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func getExecuterOptions(t *testing.T) *protocols.ExecutorOptions {
	t.Helper()

	options := testutils.DefaultOptions.Copy()
	options.Logger = &gologger.Logger{}
	testutils.Init(options)

	return testutils.NewMockExecuterOptions(options, nil)
}

func TestRequestParseAnnotationsSNI(t *testing.T) {
	t.Run("compliant-SNI-value", func(t *testing.T) {
		req := &Request{connConfiguration: &httpclientpool.Configuration{}}
		rawRequest := `@tls-sni: github.com
		GET / HTTP/1.1
		Host: {{Hostname}}`

		httpReq, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.Nil(t, err, "could not create http request")

		overrides, modified := req.parseAnnotations(rawRequest, httpReq)
		require.True(t, modified, "could not apply request annotations")
		require.Equal(t, "github.com", overrides.request.TLS.ServerName)
		require.Equal(t, "example.com", overrides.request.Host)
	})
	t.Run("non-compliant-SNI-value", func(t *testing.T) {
		req := &Request{connConfiguration: &httpclientpool.Configuration{}}
		rawRequest := `@tls-sni: ${jndi:ldap://${hostName}.test.com}
		GET / HTTP/1.1
		Host: {{Hostname}}`

		httpReq, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.Nil(t, err, "could not create http request")

		overrides, modified := req.parseAnnotations(rawRequest, httpReq)
		require.True(t, modified, "could not apply request annotations")
		require.Equal(t, "${jndi:ldap://${hostName}.test.com}", overrides.request.TLS.ServerName)
		require.Equal(t, "example.com", overrides.request.Host)
	})
	t.Run("interactsh-without-client", func(t *testing.T) {
		req := &Request{
			options:           &protocols.ExecutorOptions{},
			connConfiguration: &httpclientpool.Configuration{NoTimeout: true},
		}
		rawRequest := `@tls-sni: interactsh-url
		GET / HTTP/1.1
		Host: {{Hostname}}`

		httpReq, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)

		overrides, modified := req.parseAnnotations(rawRequest, httpReq)
		require.True(t, modified)
		require.ErrorIs(t, overrides.err, commoninteractsh.ErrInteractshClientNotInitialized)
		require.Empty(t, overrides.interactshURLs)
		require.Same(t, httpReq, overrides.request)
		require.Nil(t, overrides.cancelFunc)
	})
}

func TestRequestParseAnnotationsTimeout(t *testing.T) {
	t.Run("positive", func(t *testing.T) {
		request := &Request{
			options:           getExecuterOptions(t),
			connConfiguration: &httpclientpool.Configuration{NoTimeout: true},
		}
		rawRequest := `@timeout: 2s
		GET / HTTP/1.1
		Host: {{Hostname}}`

		httpReq, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.Nil(t, err, "could not create http request")

		overrides, modified := request.parseAnnotations(rawRequest, httpReq)
		require.NotNil(t, overrides.cancelFunc, "could not initialize valid cancel function")
		require.True(t, modified, "could not get correct modified value")

		// Verify context has deadline
		deadline, deadlined := overrides.request.Context().Deadline()
		require.True(t, deadlined, "could not get set request deadline")

		// Verify the timeout value is stored in context
		customTimeout, ok := overrides.request.Context().Value(httpclientpool.WithCustomTimeout{}).(httpclientpool.WithCustomTimeout)
		require.True(t, ok, "custom timeout not found in context")
		require.Equal(t, 2*time.Second, customTimeout.Timeout, "timeout value mismatch")

		// Verify deadline is approximately 2 seconds from now
		expectedDeadline := time.Now().Add(2 * time.Second)
		require.WithinDuration(t, expectedDeadline, deadline, 100*time.Millisecond, "deadline not set correctly")
	})

	t.Run("large-timeout", func(t *testing.T) {
		request := &Request{
			options:           getExecuterOptions(t),
			connConfiguration: &httpclientpool.Configuration{NoTimeout: true},
		}

		// Request a timeout of 10 minutes - should be capped at 5 minutes
		rawRequest := `@timeout: 10m
		GET / HTTP/1.1
		Host: {{Hostname}}`

		httpReq, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.Nil(t, err, "could not create http request")

		overrides, modified := request.parseAnnotations(rawRequest, httpReq)
		require.NotNil(t, overrides.cancelFunc, "could not initialize valid cancel function")
		require.True(t, modified, "could not get correct modified value")

		// Verify context has deadline
		deadline, deadlined := overrides.request.Context().Deadline()
		require.True(t, deadlined, "could not get set request deadline")

		// Verify the timeout was capped at 5 minutes (not 10 minutes)
		customTimeout, ok := overrides.request.Context().Value(httpclientpool.WithCustomTimeout{}).(httpclientpool.WithCustomTimeout)
		require.True(t, ok, "custom timeout not found in context")

		require.Equal(t, 5*time.Minute, customTimeout.Timeout, "timeout should be capped at 5 minutes")
		require.Less(t, customTimeout.Timeout, 10*time.Minute, "timeout should be less than requested 10 minutes")

		// Verify deadline matches the capped timeout
		expectedDeadline := time.Now().Add(5 * time.Minute)
		require.WithinDuration(t, expectedDeadline, deadline, 100*time.Millisecond, "deadline not set to capped timeout")
	})

	t.Run("below-cap-timeout", func(t *testing.T) {
		request := &Request{
			options:           getExecuterOptions(t),
			connConfiguration: &httpclientpool.Configuration{NoTimeout: true},
		}

		// Request a timeout of 2 minutes - should be allowed (below 5 minute cap)
		rawRequest := `@timeout: 2m
		GET / HTTP/1.1
		Host: {{Hostname}}`

		httpReq, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
		require.Nil(t, err, "could not create http request")

		overrides, modified := request.parseAnnotations(rawRequest, httpReq)
		require.NotNil(t, overrides.cancelFunc, "could not initialize valid cancel function")
		require.True(t, modified, "could not get correct modified value")

		// Verify context has deadline
		deadline, deadlined := overrides.request.Context().Deadline()
		require.True(t, deadlined, "could not get set request deadline")

		// Verify the timeout is NOT capped - should be 2 minutes
		customTimeout, ok := overrides.request.Context().Value(httpclientpool.WithCustomTimeout{}).(httpclientpool.WithCustomTimeout)
		require.True(t, ok, "custom timeout not found in context")

		require.Equal(t, 2*time.Minute, customTimeout.Timeout, "timeout should be the requested 2 minutes")

		// Verify deadline matches the requested timeout
		expectedDeadline := time.Now().Add(2 * time.Minute)
		require.WithinDuration(t, expectedDeadline, deadline, 100*time.Millisecond, "deadline not set to requested timeout")
	})

	t.Run("negative", func(t *testing.T) {
		request := &Request{
			options:           getExecuterOptions(t),
			connConfiguration: &httpclientpool.Configuration{},
		}
		rawRequest := `GET / HTTP/1.1
		Host: {{Hostname}}`

		httpReq, err := retryablehttp.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
		require.Nil(t, err, "could not create http request")

		newRequestWithOverrides, modified := request.parseAnnotations(rawRequest, httpReq)
		require.Nil(t, newRequestWithOverrides.cancelFunc, "cancel function should be nil")
		require.False(t, modified, "could not get correct modified value")
		_, deadlined := newRequestWithOverrides.request.Context().Deadline()
		require.False(t, deadlined, "could not get set request deadline")
	})
}

func TestRequestParseAnnotationsIgnoresLinesAfterRequestLine(t *testing.T) {
	req := &Request{connConfiguration: &httpclientpool.Configuration{}}
	rawRequest := "POST /probe HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"\r\n" +
		"hello\n@Host: http://127.0.0.1:8797\n@tls-sni: decoy.example\n"

	httpReq, err := retryablehttp.NewRequest(http.MethodPost, "https://example.com/probe", nil)
	require.NoError(t, err)

	overrides, modified := req.parseAnnotations(rawRequest, httpReq)
	require.False(t, modified)
	require.Equal(t, "https://example.com/probe", overrides.request.String())
	require.Nil(t, overrides.request.TLS)
}

// A response value reused in a raw request must stay request content even when
// one of its lines looks like an annotation. Annotations are only the lines
// before the request line.
func TestRawRequestReusingResponseWithAnnotationLine(t *testing.T) {
	tests := []struct {
		name          string
		unsafe        bool
		selfContained bool
	}{
		{name: "raw"},
		{name: "unsafe", unsafe: true},
		{name: "self-contained", selfContained: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var decoyRequests atomic.Int32
			decoy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				decoyRequests.Add(1)
			}))
			defer decoy.Close()

			responseBody := fmt.Sprintf("hello\n@Host: %s\n", decoy.URL)

			var mu sync.Mutex
			var probes []string
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/source" {
					_, _ = io.WriteString(w, responseBody)
					return
				}
				body, _ := io.ReadAll(r.Body)
				mu.Lock()
				probes = append(probes, r.Method+" "+r.URL.Path+" "+string(body))
				mu.Unlock()
			}))
			defer target.Close()

			baseURL, host, input := "", "{{Hostname}}", target.URL
			if tt.selfContained {
				// A self-contained request names its own target.
				baseURL, host, input = target.URL, strings.TrimPrefix(target.URL, "http://"), ""
			}
			probeHeaders := "Host: " + host + "\nContent-Type: text/plain\n"
			if tt.unsafe {
				// An unsafe request is sent as written, so it states its own length.
				probeHeaders += "Content-Length: {{len(tpl)}}\n"
			}
			request := &Request{
				ID:            "testing-http-response-annotation-line",
				Unsafe:        tt.unsafe,
				SelfContained: tt.selfContained,
				Raw: []string{
					"GET " + baseURL + "/source HTTP/1.1\nHost: " + host + "\n\n",
					"POST " + baseURL + "/probe HTTP/1.1\n" + probeHeaders + "\n{{tpl}}",
				},
				Operators: operators.Operators{
					Extractors: []*extractors.Extractor{{
						Name:     "tpl",
						Part:     "body",
						Type:     extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor},
						Regex:    []string{`(?s).+`},
						Internal: true,
					}},
				},
			}

			options := testutils.DefaultOptions
			testutils.Init(options)
			executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
				ID:   request.ID,
				Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Info}, Name: "test"},
			})
			require.NoError(t, request.Compile(executerOpts))

			err := request.ExecuteWithResults(
				contextargs.NewWithInput(context.Background(), input),
				make(output.InternalEvent),
				make(output.InternalEvent),
				func(*output.InternalWrappedEvent) {},
			)
			require.NoError(t, err)

			require.Zero(t, decoyRequests.Load(), "a response line must not redirect the request")
			mu.Lock()
			defer mu.Unlock()
			require.Equal(t, []string{"POST /probe " + responseBody}, probes)
		})
	}
}

func TestTemplateAnnotationsAfterRequestLine(t *testing.T) {
	const request = "GET / HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n@timeout: 5s\r\n@once\r\n"

	require.False(t, hasTimeoutAnnotation(request))
	require.True(t, hasTimeoutAnnotation("@timeout: 5s\r\n"+request))

	_, hasFlowOverride := parseFlowAnnotations(request)
	require.False(t, hasFlowOverride)
	mark, hasFlowOverride := parseFlowAnnotations("@once\r\n" + request)
	require.True(t, hasFlowOverride)
	require.Equal(t, Once, mark)
}
