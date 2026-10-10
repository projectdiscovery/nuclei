package http

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func TestNeedsFullResponse(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)

	t.Run("body matcher does not need full response", func(t *testing.T) {
		req := &Request{
			ID:     "body-only",
			Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
			Operators: operators.Operators{
				Matchers: []*matchers.Matcher{{
					Part:  "body",
					Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
					Words: []string{"test"},
				}},
			},
		}
		execOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "body-only"})
		require.NoError(t, req.Compile(execOpts))
		require.False(t, req.needsFullResponse(nil))
	})

	t.Run("header matcher does not need full response", func(t *testing.T) {
		req := &Request{
			ID:     "header-only",
			Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
			Operators: operators.Operators{
				Matchers: []*matchers.Matcher{{
					Part:  "header",
					Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
					Words: []string{"Content-Type"},
				}},
			},
		}
		execOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "header-only"})
		require.NoError(t, req.Compile(execOpts))
		require.False(t, req.needsFullResponse(nil))
	})

	t.Run("status matcher does not need full response", func(t *testing.T) {
		req := &Request{
			ID:     "status-only",
			Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
			Operators: operators.Operators{
				Matchers: []*matchers.Matcher{{
					Type:   matchers.MatcherTypeHolder{MatcherType: matchers.StatusMatcher},
					Status: []int{200},
				}},
			},
		}
		execOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "status-only"})
		require.NoError(t, req.Compile(execOpts))
		require.False(t, req.needsFullResponse(nil))
	})

	t.Run("matcher with part response needs full response", func(t *testing.T) {
		req := &Request{
			ID:     "part-response",
			Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
			Operators: operators.Operators{
				Matchers: []*matchers.Matcher{{
					Part:  "response",
					Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
					Words: []string{"test"},
				}},
			},
		}
		execOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "part-response"})
		require.NoError(t, req.Compile(execOpts))
		require.True(t, req.needsFullResponse(nil))
	})

	t.Run("matcher with part all needs full response", func(t *testing.T) {
		req := &Request{
			ID:     "part-all",
			Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
			Operators: operators.Operators{
				Matchers: []*matchers.Matcher{{
					Part:  "all",
					Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
					Words: []string{"test"},
				}},
			},
		}
		execOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "part-all"})
		require.NoError(t, req.Compile(execOpts))
		require.True(t, req.needsFullResponse(nil))
	})

	t.Run("dsl matcher without response does not need full response", func(t *testing.T) {
		req := &Request{
			ID:     "dsl-body",
			Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
			Operators: operators.Operators{
				Matchers: []*matchers.Matcher{{
					Type: matchers.MatcherTypeHolder{MatcherType: matchers.DSLMatcher},
					DSL:  []string{"status_code == 200 && contains(body, 'test')"},
				}},
			},
		}
		execOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "dsl-body"})
		require.NoError(t, req.Compile(execOpts))
		require.False(t, req.needsFullResponse(nil))
	})

	t.Run("dsl matcher with response needs full response", func(t *testing.T) {
		req := &Request{
			ID:     "dsl-response",
			Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
			Operators: operators.Operators{
				Matchers: []*matchers.Matcher{{
					Type: matchers.MatcherTypeHolder{MatcherType: matchers.DSLMatcher},
					DSL:  []string{"contains(response, 'test')"},
				}},
			},
		}
		execOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "dsl-response"})
		require.NoError(t, req.Compile(execOpts))
		require.True(t, req.needsFullResponse(nil))
	})

	t.Run("dsl matcher with response prefix needs full response", func(t *testing.T) {
		req := &Request{
			ID:     "dsl-response-history",
			Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
			Operators: operators.Operators{
				Matchers: []*matchers.Matcher{{
					Type: matchers.MatcherTypeHolder{MatcherType: matchers.DSLMatcher},
					DSL:  []string{"contains(response_1, 'test')"},
				}},
			},
		}
		execOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "dsl-response-history"})
		require.NoError(t, req.Compile(execOpts))
		require.True(t, req.needsFullResponse(nil))
	})

	t.Run("extractor with part response needs full response", func(t *testing.T) {
		req := &Request{
			ID:     "extractor-part-response",
			Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
			Operators: operators.Operators{
				Extractors: []*extractors.Extractor{{
					Part:  "response",
					Type:  extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor},
					Regex: []string{"test"},
				}},
			},
		}
		execOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "extractor-part-response"})
		require.NoError(t, req.Compile(execOpts))
		require.True(t, req.needsFullResponse(nil))
	})

	t.Run("extractor with kval response needs full response", func(t *testing.T) {
		req := &Request{
			ID:     "extractor-kval-response",
			Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
			Operators: operators.Operators{
				Extractors: []*extractors.Extractor{{
					Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.KValExtractor},
					KVal: []string{"response"},
				}},
			},
		}
		execOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "extractor-kval-response"})
		require.NoError(t, req.Compile(execOpts))
		require.True(t, req.needsFullResponse(nil))
	})

	t.Run("debug options require full response", func(t *testing.T) {
		debugOpts := *testutils.DefaultOptions
		debugOpts.Debug = true

		req := &Request{
			ID:     "debug-flag",
			Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
			Operators: operators.Operators{
				Matchers: []*matchers.Matcher{{
					Part:  "body",
					Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
					Words: []string{"test"},
				}},
			},
		}
		execOpts := testutils.NewMockExecuterOptions(&debugOpts, &testutils.TemplateInfo{ID: "debug-flag"})
		require.NoError(t, req.Compile(execOpts))
		require.True(t, req.needsFullResponse(nil))
	})

	t.Run("http stats option requires full response", func(t *testing.T) {
		statsOpts := *testutils.DefaultOptions
		statsOpts.HTTPStats = true

		req := &Request{
			ID:     "http-stats-flag",
			Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
			Operators: operators.Operators{
				Matchers: []*matchers.Matcher{{
					Part:  "body",
					Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
					Words: []string{"test"},
				}},
			},
		}
		execOpts := testutils.NewMockExecuterOptions(&statsOpts, &testutils.TemplateInfo{ID: "http-stats-flag"})
		require.NoError(t, req.Compile(execOpts))
		require.True(t, req.needsFullResponse(nil))
	})
}

func TestExecuteRequestDeferredResponse_NoMatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Header", "present")
		_, _ = fmt.Fprintf(w, "response body content")
	}))
	defer ts.Close()

	options := testutils.DefaultOptions
	testutils.Init(options)

	req := &Request{
		ID:     "defer-no-match",
		Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
		Path:   []string{"{{BaseURL}}"},
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Part:  "body",
				Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
				Words: []string{"nonexistent-needle"},
			}},
		},
	}

	execOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "defer-no-match",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Info}, Name: "test"},
	})
	require.NoError(t, req.Compile(execOpts))

	var capturedEvent *output.InternalWrappedEvent
	ctxArgs := contextargs.NewWithInput(context.Background(), ts.URL)
	err := req.ExecuteWithResults(ctxArgs, make(output.InternalEvent), make(output.InternalEvent), func(event *output.InternalWrappedEvent) {
		capturedEvent = event
	})
	require.NoError(t, err)
	require.NotNil(t, capturedEvent)
	require.False(t, capturedEvent.HasResults())

	// Response string should be deferred/empty since operators did not need it and no match occurred
	require.Equal(t, "", capturedEvent.InternalEvent["response"])
	// Body and headers are still fully populated
	require.Contains(t, types.ToString(capturedEvent.InternalEvent["body"]), "response body content")
	require.Contains(t, types.ToString(capturedEvent.InternalEvent["all_headers"]), "X-Custom-Header")
}

func TestExecuteRequestDeferredResponse_WithMatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Server", "nuclei-test")
		_, _ = fmt.Fprintf(w, "secret-vulnerability-found")
	}))
	defer ts.Close()

	options := testutils.DefaultOptions
	options.ResponseSaveSize = 1024 * 1024
	testutils.Init(options)

	req := &Request{
		ID:     "defer-with-match",
		Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
		Path:   []string{"{{BaseURL}}"},
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Part:  "body",
				Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
				Words: []string{"secret-vulnerability-found"},
			}},
		},
	}

	execOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "defer-with-match",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.High}, Name: "test"},
	})
	require.NoError(t, req.Compile(execOpts))

	var capturedEvent *output.InternalWrappedEvent
	ctxArgs := contextargs.NewWithInput(context.Background(), ts.URL)
	err := req.ExecuteWithResults(ctxArgs, make(output.InternalEvent), make(output.InternalEvent), func(event *output.InternalWrappedEvent) {
		capturedEvent = event
	})
	require.NoError(t, err)
	require.NotNil(t, capturedEvent)
	require.True(t, capturedEvent.HasResults())

	// Upon match, lazy evaluation populates the full response
	require.NotEmpty(t, capturedEvent.InternalEvent["response"])
	require.Contains(t, types.ToString(capturedEvent.InternalEvent["response"]), "secret-vulnerability-found")
	require.Contains(t, types.ToString(capturedEvent.InternalEvent["response"]), "X-Server: nuclei-test")

	// Result event also has the full response populated
	require.Len(t, capturedEvent.Results, 1)
	require.Contains(t, capturedEvent.Results[0].Response, "secret-vulnerability-found")
}

func TestExecuteRequestFullResponse_WhenOperatorRequires(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom", "active")
		_, _ = fmt.Fprintf(w, "body data")
	}))
	defer ts.Close()

	options := testutils.DefaultOptions
	options.ResponseSaveSize = 1024 * 1024
	testutils.Init(options)

	req := &Request{
		ID:     "operator-requires-response",
		Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
		Path:   []string{"{{BaseURL}}"},
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Part:  "response",
				Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
				Words: []string{"X-Custom: active"},
			}},
		},
	}

	execOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "operator-requires-response",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Medium}, Name: "test"},
	})
	require.NoError(t, req.Compile(execOpts))

	var capturedEvent *output.InternalWrappedEvent
	ctxArgs := contextargs.NewWithInput(context.Background(), ts.URL)
	err := req.ExecuteWithResults(ctxArgs, make(output.InternalEvent), make(output.InternalEvent), func(event *output.InternalWrappedEvent) {
		capturedEvent = event
	})
	require.NoError(t, err)
	require.NotNil(t, capturedEvent)
	require.True(t, capturedEvent.HasResults())
	require.Contains(t, types.ToString(capturedEvent.InternalEvent["response"]), "X-Custom: active")
	require.Len(t, capturedEvent.Results, 1)
	require.Contains(t, capturedEvent.Results[0].Response, "X-Custom: active")
}

func TestStatusMatcherSnippet_HeaderFallback(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)

	req := &Request{
		ID:     "status-fallback",
		Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
	}
	execOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{ID: "status-fallback"})
	require.NoError(t, req.Compile(execOpts))

	matcher := &matchers.Matcher{
		Type:   matchers.MatcherTypeHolder{MatcherType: matchers.StatusMatcher},
		Status: []int{200},
	}
	require.NoError(t, matcher.CompileMatchers())

	// Data has empty response, but header is present
	eventData := map[string]interface{}{
		"status_code": 200,
		"response":    "",
		"body":        "",
		"header":      "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n",
	}

	isMatch, snippets := req.Match(eventData, matcher)
	require.True(t, isMatch)
	require.Len(t, snippets, 1)
	require.Equal(t, "HTTP/1.1 200", snippets[0])
}
