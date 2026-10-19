package http

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tarunKoyalwar/goleak"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/retryablehttp-go"
	"io"
)

func executeDynamicHTTPTestRequest(t *testing.T, request *Request, target string) {
	t.Helper()
	options := testutils.DefaultOptions
	testutils.Init(options)
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID: request.ID,
		Info: model.Info{
			SeverityHolder: severity.Holder{Severity: severity.Low},
			Name:           "test",
		},
	})
	require.NoError(t, request.Compile(executerOpts))
	require.NoError(t, request.ExecuteWithResults(
		contextargs.NewWithInput(context.Background(), target),
		make(output.InternalEvent),
		make(output.InternalEvent),
		func(*output.InternalWrappedEvent) {},
	))
}

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
			_, _ = fmt.Fprintf(w, `User-agent: Googlebot
Disallow: /a
Disallow: /b
Disallow: /c`)
		default:
			_, _ = fmt.Fprintf(w, `match %v`, r.URL.Path)
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
		ctxArgs := contextargs.NewWithInput(context.Background(), ts.URL)
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

func TestHTTPExtractMultipleReusePreservesBranchValues(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)

	request := &Request{
		ID: "testing-http-branch-values",
		Raw: []string{
			"GET /capabilities HTTP/1.1\nHost: {{Hostname}}",
			"GET /metadata/{{name}} HTTP/1.1\nHost: {{Hostname}}",
			"GET /probe/{{name}}/{{column}} HTTP/1.1\nHost: {{Hostname}}",
		},
		Operators: operators.Operators{
			Extractors: []*extractors.Extractor{
				{
					Part:       "body_1",
					Name:       "name",
					Type:       extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor},
					Regex:      []string{`name=([a-z]+)`},
					RegexGroup: 1,
					Internal:   true,
				},
				{
					Part:       "body_2",
					Name:       "column",
					Type:       extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor},
					Regex:      []string{`column=([a-z0-9]+)`},
					RegexGroup: 1,
					Internal:   true,
				},
			},
		},
		IterateAll: true,
	}

	var mutex sync.Mutex
	probes := make(map[string]int)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/capabilities":
			_, _ = fmt.Fprint(w, "name=alpha name=beta")
		case "/metadata/alpha":
			_, _ = fmt.Fprint(w, "column=a1 column=a2")
		case "/metadata/beta":
			_, _ = fmt.Fprint(w, "column=b1")
		default:
			mutex.Lock()
			probes[r.URL.Path]++
			mutex.Unlock()
		}
	}))
	defer ts.Close()

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID: request.ID,
		Info: model.Info{
			SeverityHolder: severity.Holder{Severity: severity.Low},
			Name:           "test",
		},
	})
	require.NoError(t, request.Compile(executerOpts))

	err := request.ExecuteWithResults(
		contextargs.NewWithInput(context.Background(), ts.URL),
		make(output.InternalEvent),
		make(output.InternalEvent),
		func(*output.InternalWrappedEvent) {},
	)
	require.NoError(t, err)
	require.Equal(t, map[string]int{
		"/probe/alpha/a1": 1,
		"/probe/alpha/a2": 1,
		"/probe/beta/b1":  1,
	}, probes)
}

func TestHTTPExtractMultipleReuseReplacesReextractedValue(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)

	request := &Request{
		ID: "testing-http-reextracted-value",
		Raw: []string{
			"GET /session HTTP/1.1\nHost: {{Hostname}}",
			"GET /refresh/{{token}} HTTP/1.1\nHost: {{Hostname}}",
			"GET /use/{{token}} HTTP/1.1\nHost: {{Hostname}}",
			"GET /final/{{token}} HTTP/1.1\nHost: {{Hostname}}",
		},
		Operators: operators.Operators{
			Extractors: []*extractors.Extractor{
				{
					Part:       "body_1",
					Name:       "token",
					Type:       extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor},
					Regex:      []string{`token=([a-z]+)`},
					RegexGroup: 1,
					Internal:   true,
				},
				{
					Part:       "body_2",
					Name:       "token",
					Type:       extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor},
					Regex:      []string{`token=([a-z]+)`},
					RegexGroup: 1,
					Internal:   true,
				},
			},
		},
		IterateAll: true,
	}

	var mutex sync.Mutex
	requests := make(map[string]int)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mutex.Lock()
		requests[r.URL.Path]++
		mutex.Unlock()
		switch r.URL.Path {
		case "/session":
			_, _ = fmt.Fprint(w, "token=old")
		case "/refresh/old":
			_, _ = fmt.Fprint(w, "token=new token=next")
		}
	}))
	defer ts.Close()

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID: request.ID,
		Info: model.Info{
			SeverityHolder: severity.Holder{Severity: severity.Low},
			Name:           "test",
		},
	})
	require.NoError(t, request.Compile(executerOpts))

	err := request.ExecuteWithResults(
		contextargs.NewWithInput(context.Background(), ts.URL),
		make(output.InternalEvent),
		make(output.InternalEvent),
		func(*output.InternalWrappedEvent) {},
	)
	require.NoError(t, err)
	require.Equal(t, map[string]int{
		"/session":     1,
		"/refresh/old": 1,
		"/use/new":     1,
		"/use/next":    1,
		"/final/new":   1,
		"/final/next":  1,
	}, requests)
}

func TestExpandDynamicValueContextsReplacesReextractedValueWithoutIteration(t *testing.T) {
	parent := dynamicValueContext{
		values: map[string]interface{}{"token": "old"},
	}

	contexts := expandDynamicValueContexts(parent, map[string][]string{"token": {"new", "next"}}, false)

	require.Len(t, contexts, 1)
	require.Equal(t, "new", contexts[0].values["token"])
}

func TestHTTPExtractMultipleReusePreservesOnceValuesAcrossPayloads(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)

	request := &Request{
		ID: "testing-http-once-payload-values",
		Raw: []string{
			"@once\nGET /token HTTP/1.1\nHost: {{Hostname}}",
			"GET /use/{{token}}/{{item}} HTTP/1.1\nHost: {{Hostname}}",
		},
		Payloads: map[string]interface{}{
			"item": []string{"first", "second"},
		},
		Operators: operators.Operators{
			Extractors: []*extractors.Extractor{{
				Part:       "body_1",
				Name:       "token",
				Type:       extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor},
				Regex:      []string{`token=([a-z]+)`},
				RegexGroup: 1,
				Internal:   true,
			}},
		},
		IterateAll: true,
	}

	var mutex sync.Mutex
	requests := make(map[string]int)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_, _ = fmt.Fprint(w, "token=shared")
			return
		}
		mutex.Lock()
		requests[r.URL.Path]++
		mutex.Unlock()
	}))
	defer ts.Close()

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID: request.ID,
		Info: model.Info{
			SeverityHolder: severity.Holder{Severity: severity.Low},
			Name:           "test",
		},
	})
	require.NoError(t, request.Compile(executerOpts))

	err := request.ExecuteWithResults(
		contextargs.NewWithInput(context.Background(), ts.URL),
		make(output.InternalEvent),
		make(output.InternalEvent),
		func(*output.InternalWrappedEvent) {},
	)
	require.NoError(t, err)
	require.Equal(t, map[string]int{
		"/use/shared/first":  1,
		"/use/shared/second": 1,
	}, requests)
}

func TestHTTPExtractMultipleReuseDoesNotPersistPayloadValuesBeforeOnce(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)

	request := &Request{
		ID: "testing-http-payload-values-before-once",
		Raw: []string{
			"GET /seed/{{item}} HTTP/1.1\nHost: {{Hostname}}",
			"@once\nGET /token HTTP/1.1\nHost: {{Hostname}}",
			"GET /use/{{branch}}/{{token}}/{{item}} HTTP/1.1\nHost: {{Hostname}}",
		},
		Payloads: map[string]interface{}{
			"item": []string{"first", "second"},
		},
		Operators: operators.Operators{
			Extractors: []*extractors.Extractor{
				{
					Part:       "body_1",
					Name:       "branch",
					Type:       extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor},
					Regex:      []string{`branch=([a-z]+)`},
					RegexGroup: 1,
					Internal:   true,
				},
				{
					Part:       "body_2",
					Name:       "token",
					Type:       extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor},
					Regex:      []string{`token=([a-z]+)`},
					RegexGroup: 1,
					Internal:   true,
				},
			},
		},
		IterateAll: true,
	}

	var mutex sync.Mutex
	requests := make(map[string]int)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/seed/"):
			_, _ = fmt.Fprintf(w, "branch=%s", strings.TrimPrefix(r.URL.Path, "/seed/"))
		case r.URL.Path == "/token":
			_, _ = fmt.Fprint(w, "token=shared")
		default:
			mutex.Lock()
			requests[r.URL.Path]++
			mutex.Unlock()
		}
	}))
	defer ts.Close()

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID: request.ID,
		Info: model.Info{
			SeverityHolder: severity.Holder{Severity: severity.Low},
			Name:           "test",
		},
	})
	require.NoError(t, request.Compile(executerOpts))

	err := request.ExecuteWithResults(
		contextargs.NewWithInput(context.Background(), ts.URL),
		make(output.InternalEvent),
		make(output.InternalEvent),
		func(*output.InternalWrappedEvent) {},
	)
	require.NoError(t, err)
	require.Equal(t, map[string]int{
		"/use/first/shared/first":   1,
		"/use/second/shared/second": 1,
	}, requests)
}

func TestHTTPExtractMultipleReuseSkipsOnlyMissingBranch(t *testing.T) {
	request := &Request{
		ID: "testing-http-missing-branch",
		Raw: []string{
			"GET /capabilities HTTP/1.1\nHost: {{Hostname}}",
			"GET /metadata/{{name}} HTTP/1.1\nHost: {{Hostname}}",
			"GET /probe/{{name}}/{{column}} HTTP/1.1\nHost: {{Hostname}}",
		},
		Operators: operators.Operators{Extractors: []*extractors.Extractor{
			{Part: "body_1", Name: "name", Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor}, Regex: []string{`name=([a-z]+)`}, RegexGroup: 1, Internal: true},
			{Part: "body_2", Name: "column", Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor}, Regex: []string{`column=([a-z0-9]+)`}, RegexGroup: 1, Internal: true},
		}},
		IterateAll: true,
	}

	var mutex sync.Mutex
	probes := make(map[string]int)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/capabilities":
			_, _ = fmt.Fprint(w, "name=alpha name=beta name=gamma")
		case "/metadata/beta":
			_, _ = fmt.Fprint(w, "column=b1")
		case "/metadata/gamma":
			_, _ = fmt.Fprint(w, "column=g1")
		case "/metadata/alpha":
		default:
			mutex.Lock()
			probes[r.URL.Path]++
			mutex.Unlock()
		}
	}))
	defer ts.Close()

	executeDynamicHTTPTestRequest(t, request, ts.URL)
	require.Equal(t, map[string]int{"/probe/beta/b1": 1, "/probe/gamma/g1": 1}, probes)
}

func TestHTTPExtractMultipleReuseKeepsPayloadFallback(t *testing.T) {
	request := &Request{
		ID: "testing-http-payload-fallback",
		Raw: []string{
			"GET /create HTTP/1.1\nHost: {{Hostname}}",
			"GET /use/{{rid}}/{{item}} HTTP/1.1\nHost: {{Hostname}}",
		},
		Payloads: map[string]interface{}{"item": []string{"p1", "p2", "p3"}},
		Operators: operators.Operators{Extractors: []*extractors.Extractor{{
			Part: "body", Name: "rid", Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor}, Regex: []string{`rid=([a-z]+)`}, RegexGroup: 1, Internal: true,
		}}},
		IterateAll: true,
	}

	var createCount atomic.Int32
	var mutex sync.Mutex
	uses := make(map[string]int)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/create" {
			if createCount.Add(1) == 1 {
				_, _ = fmt.Fprint(w, "rid=abc")
			}
			return
		}
		mutex.Lock()
		uses[r.URL.Path]++
		mutex.Unlock()
	}))
	defer ts.Close()

	executeDynamicHTTPTestRequest(t, request, ts.URL)
	require.Equal(t, map[string]int{"/use/abc/p1": 1, "/use/abc/p2": 1, "/use/abc/p3": 1}, uses)
}

func TestHTTPExtractMultipleReuseUsesLatestReextractedValue(t *testing.T) {
	request := &Request{
		ID: "testing-http-latest-reextracted-value",
		Raw: []string{
			"GET /one HTTP/1.1\nHost: {{Hostname}}",
			"GET /two HTTP/1.1\nHost: {{Hostname}}",
			"GET /three HTTP/1.1\nHost: {{Hostname}}",
			"GET /use/{{csrf}} HTTP/1.1\nHost: {{Hostname}}",
		},
		Operators: operators.Operators{Extractors: []*extractors.Extractor{{
			Part: "body", Name: "csrf", Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor}, Regex: []string{`csrf=([a-z]+)`}, RegexGroup: 1, Internal: true,
		}}},
	}

	var mutex sync.Mutex
	uses := make(map[string]int)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/one":
			_, _ = fmt.Fprint(w, "csrf=aaa")
		case "/two":
			_, _ = fmt.Fprint(w, "csrf=bbb")
		case "/three":
			_, _ = fmt.Fprint(w, "csrf=aaa")
		default:
			mutex.Lock()
			uses[r.URL.Path]++
			mutex.Unlock()
		}
	}))
	defer ts.Close()

	executeDynamicHTTPTestRequest(t, request, ts.URL)
	require.Equal(t, map[string]int{"/use/aaa": 1}, uses)
}

func TestHTTPExtractMultipleReuseRetainsParentValueWhenReextracted(t *testing.T) {
	request := &Request{
		ID: "testing-http-parent-reextracted-value",
		Raw: []string{
			"GET /items HTTP/1.1\nHost: {{Hostname}}",
			"GET /item/{{id}} HTTP/1.1\nHost: {{Hostname}}",
			"GET /delete/{{id}} HTTP/1.1\nHost: {{Hostname}}",
		},
		Operators: operators.Operators{Extractors: []*extractors.Extractor{{
			Part: "body", Name: "id", Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor}, Regex: []string{`id=([0-9]+)`}, RegexGroup: 1, Internal: true,
		}}},
		IterateAll: true,
	}

	var mutex sync.Mutex
	deletes := make(map[string]int)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/items":
			_, _ = fmt.Fprint(w, "id=1 id=2")
		case "/item/1":
			_, _ = fmt.Fprint(w, "id=1 id=9")
		case "/item/2":
			_, _ = fmt.Fprint(w, "id=2")
		default:
			mutex.Lock()
			deletes[r.URL.Path]++
			mutex.Unlock()
		}
	}))
	defer ts.Close()

	executeDynamicHTTPTestRequest(t, request, ts.URL)
	require.Equal(t, map[string]int{"/delete/1": 1, "/delete/2": 1, "/delete/9": 1}, deletes)
}

func TestHTTPExtractMultipleReuseRunsOnceRequestOnceAcrossBranches(t *testing.T) {
	request := &Request{
		ID: "testing-http-once-across-branches",
		Raw: []string{
			"GET /list HTTP/1.1\nHost: {{Hostname}}",
			"@once\nGET /token HTTP/1.1\nHost: {{Hostname}}",
			"GET /use/{{id}}/{{token}}/{{item}} HTTP/1.1\nHost: {{Hostname}}",
		},
		Payloads: map[string]interface{}{"item": []string{"x", "y", "z"}},
		Operators: operators.Operators{Extractors: []*extractors.Extractor{
			{Part: "body_1", Name: "id", Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor}, Regex: []string{`id=([a-z]+)`}, RegexGroup: 1, Internal: true},
			{Part: "body_2", Name: "token", Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor}, Regex: []string{`token=([a-z0-9]+)`}, RegexGroup: 1, Internal: true},
		}},
		IterateAll: true,
	}

	var tokenCount atomic.Int32
	var mutex sync.Mutex
	uses := make(map[string]int)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/list":
			_, _ = fmt.Fprint(w, "id=a id=b")
		case "/token":
			_, _ = fmt.Fprintf(w, "token=t%d", tokenCount.Add(1))
		default:
			mutex.Lock()
			uses[r.URL.Path]++
			mutex.Unlock()
		}
	}))
	defer ts.Close()

	executeDynamicHTTPTestRequest(t, request, ts.URL)
	require.EqualValues(t, 1, tokenCount.Load())
	require.Equal(t, map[string]int{
		"/use/a/t1/x": 1, "/use/b/t1/x": 1,
		"/use/a/t1/y": 1, "/use/b/t1/y": 1,
		"/use/a/t1/z": 1, "/use/b/t1/z": 1,
	}, uses)
}

func TestHTTPExtractMultipleReuseKeepsResponseHistoryPerBranch(t *testing.T) {
	request := &Request{
		ID: "testing-http-branch-response-history",
		Raw: []string{
			"GET /items HTTP/1.1\nHost: {{Hostname}}",
			"GET /item/{{id}} HTTP/1.1\nHost: {{Hostname}}",
			"GET /noop/{{id}} HTTP/1.1\nHost: {{Hostname}}",
			"GET /use/{{id}}/{{token}} HTTP/1.1\nHost: {{Hostname}}",
		},
		Operators: operators.Operators{Extractors: []*extractors.Extractor{
			{Part: "body_1", Name: "id", Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor}, Regex: []string{`id=([a-z]+)`}, RegexGroup: 1, Internal: true},
			{Part: "body_2", Name: "token", Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor}, Regex: []string{`token=([a-z]+)`}, RegexGroup: 1, Internal: true},
		}},
		IterateAll: true,
	}

	var mutex sync.Mutex
	uses := make(map[string]int)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/items":
			_, _ = fmt.Fprint(w, "id=a id=b")
		case "/item/a":
			_, _ = fmt.Fprint(w, "token=a")
		case "/item/b":
			_, _ = fmt.Fprint(w, "token=b")
		case "/noop/a", "/noop/b":
		default:
			mutex.Lock()
			uses[r.URL.Path]++
			mutex.Unlock()
		}
	}))
	defer ts.Close()

	executeDynamicHTTPTestRequest(t, request, ts.URL)
	require.Equal(t, map[string]int{"/use/a/a": 1, "/use/b/b": 1}, uses)
}

func TestHTTPExtractMultipleReuseCopiesRenderedPayloadPerBranch(t *testing.T) {
	request := &Request{
		ID: "testing-http-payload-per-branch",
		Raw: []string{
			"GET /names HTTP/1.1\nHost: {{Hostname}}",
			"GET /x/{{item}} HTTP/1.1\nHost: {{Hostname}}",
		},
		Payloads: map[string]interface{}{"item": []string{"{{name}}-p"}},
		Operators: operators.Operators{Extractors: []*extractors.Extractor{{
			Part: "body_1", Name: "name", Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor}, Regex: []string{`name=([a-z]+)`}, RegexGroup: 1, Internal: true,
		}}},
		IterateAll: true,
	}

	var mutex sync.Mutex
	uses := make(map[string]int)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/names" {
			_, _ = fmt.Fprint(w, "name=alpha name=beta")
			return
		}
		mutex.Lock()
		uses[r.URL.Path]++
		mutex.Unlock()
	}))
	defer ts.Close()

	executeDynamicHTTPTestRequest(t, request, ts.URL)
	require.Equal(t, map[string]int{"/x/alpha-p": 1, "/x/beta-p": 1}, uses)
}

func TestHTTPExtractMultipleReuseDeduplicatesNewValues(t *testing.T) {
	request := &Request{
		ID:  "testing-http-deduplicate-values",
		Raw: []string{"GET /seed HTTP/1.1\nHost: {{Hostname}}", "GET /use/{{v}} HTTP/1.1\nHost: {{Hostname}}"},
		Operators: operators.Operators{Extractors: []*extractors.Extractor{
			{Part: "body", Name: "v", Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor}, Regex: []string{`value=([a-z]+)`}, RegexGroup: 1, Internal: true},
			{Part: "header", Name: "v", Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor}, Regex: []string{`X-Value: ([a-z]+)`}, RegexGroup: 1, Internal: true},
		}},
		IterateAll: true,
	}

	var useCount atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/seed" {
			w.Header().Set("X-Value", "abc")
			_, _ = fmt.Fprint(w, "value=abc")
			return
		}
		useCount.Add(1)
	}))
	defer ts.Close()

	executeDynamicHTTPTestRequest(t, request, ts.URL)
	require.EqualValues(t, 1, useCount.Load())
}

func TestHTTPExtractMultipleReuseOverridesTemplateContextPerBranch(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)
	request := &Request{
		ID:  "testing-http-template-context-branch",
		Raw: []string{"GET /seed HTTP/1.1\nHost: {{Hostname}}", "GET /use/{{id}} HTTP/1.1\nHost: {{Hostname}}"},
		Operators: operators.Operators{Extractors: []*extractors.Extractor{{
			Part: "body_1", Name: "id", Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor}, Regex: []string{`id=([a-z]+)`}, RegexGroup: 1, Internal: true,
		}}},
		IterateAll: true,
	}

	var mutex sync.Mutex
	uses := make(map[string]int)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/seed" {
			_, _ = fmt.Fprint(w, "id=alpha id=beta")
			return
		}
		mutex.Lock()
		uses[r.URL.Path]++
		mutex.Unlock()
	}))
	defer ts.Close()

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID: request.ID,
		Info: model.Info{
			SeverityHolder: severity.Holder{Severity: severity.Low},
			Name:           "test",
		},
	})
	require.NoError(t, request.Compile(executerOpts))
	input := contextargs.NewWithInput(context.Background(), ts.URL)
	executerOpts.GetTemplateCtx(input.MetaInput).Set("id", "stale")
	require.NoError(t, request.ExecuteWithResults(
		input,
		output.InternalEvent(executerOpts.GetTemplateCtx(input.MetaInput).GetAll()),
		make(output.InternalEvent),
		func(*output.InternalWrappedEvent) {},
	))
	require.Equal(t, map[string]int{"/use/alpha": 1, "/use/beta": 1}, uses)
}

func TestHTTPExtractMultipleReuseIteratesInitialDynamicValues(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)
	request := &Request{
		ID:         "testing-http-initial-dynamic-values",
		Raw:        []string{"GET /use/{{id}} HTTP/1.1\nHost: {{Hostname}}"},
		IterateAll: true,
	}

	var mutex sync.Mutex
	uses := make(map[string]int)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mutex.Lock()
		uses[r.URL.Path]++
		mutex.Unlock()
	}))
	defer ts.Close()

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID: request.ID,
		Info: model.Info{
			SeverityHolder: severity.Holder{Severity: severity.Low},
			Name:           "test",
		},
	})
	require.NoError(t, request.Compile(executerOpts))
	require.NoError(t, request.ExecuteWithResults(
		contextargs.NewWithInput(context.Background(), ts.URL),
		output.InternalEvent{"id": []string{"alpha", "beta"}},
		make(output.InternalEvent),
		func(*output.InternalWrappedEvent) {},
	))
	require.Equal(t, map[string]int{"/use/alpha": 1, "/use/beta": 1}, uses)
}

func TestHTTPExtractMultipleReuseStopsOnceBranchesAfterCancellation(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)
	request := &Request{
		ID: "testing-http-once-branch-cancellation",
		Raw: []string{
			"GET /seed HTTP/1.1\nHost: {{Hostname}}",
			"@once\nGET /token/{{missing}} HTTP/1.1\nHost: {{Hostname}}",
		},
		Operators: operators.Operators{Extractors: []*extractors.Extractor{{
			Part: "body_1", Name: "id", Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor}, Regex: []string{`id=([a-z]+)`}, RegexGroup: 1, Internal: true,
		}}},
		IterateAll: true,
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "id=alpha id=beta")
	}))
	defer ts.Close()

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID: request.ID,
		Info: model.Info{
			SeverityHolder: severity.Holder{Severity: severity.Low},
			Name:           "test",
		},
	})
	executerOpts.RateLimiter.Stop()
	executerOpts.RateLimiter = ratelimit.New(context.Background(), 1, 500*time.Millisecond)
	t.Cleanup(executerOpts.RateLimiter.Stop)
	require.NoError(t, request.Compile(executerOpts))

	ctx, cancel := context.WithCancel(context.Background())
	cancelTimer := time.AfterFunc(100*time.Millisecond, cancel)
	t.Cleanup(func() {
		cancelTimer.Stop()
		cancel()
	})
	startedAt := time.Now()
	err := request.ExecuteWithResults(
		contextargs.NewWithInput(ctx, ts.URL),
		make(output.InternalEvent),
		make(output.InternalEvent),
		func(*output.InternalWrappedEvent) {},
	)
	require.ErrorIs(t, err, context.Canceled)
	require.Less(t, time.Since(startedAt), 750*time.Millisecond)
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
		ctxArgs := contextargs.NewWithInput(context.Background(), ts.URL)
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
		ctxArgs := contextargs.NewWithInput(context.Background(), ts.URL)
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

// consult @Ice3man543 before making any breaking changes to this test (context: vuln_hash)
func TestReqURLPattern(t *testing.T) {
	options := testutils.DefaultOptions

	// assume this was a preprocessor
	// {{randstr}} => 2eNU2kbrOcUDzhnUL1RGvSo1it7
	testutils.Init(options)
	templateID := "testing-http"
	request := &Request{
		ID: templateID,
		Raw: []string{
			`GET /{{rand_char("abc")}}/{{interactsh-url}}/123?query={{rand_int(1, 10)}}&data=2eNU2kbrOcUDzhnUL1RGvSo1it7 HTTP/1.1
			Host: {{Hostname}}
			User-Agent: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0
			Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
			Accept-Language: en-US,en;q=0.5
			`,
		},
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Type: matchers.MatcherTypeHolder{MatcherType: matchers.DSLMatcher},
				DSL:  []string{"true"},
			}},
		},
		IterateAll: true,
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// always return 200
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`match`))
	}))
	defer ts.Close()

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	client, _ := interactsh.New(interactsh.DefaultOptions(executerOpts.Output, nil, executerOpts.Progress))
	executerOpts.Interactsh = client
	defer client.Close()
	executerOpts.ExportReqURLPattern = true

	// this is how generated constants are added to template
	// generated constants are preprocessors that are executed while loading once
	executerOpts.Constants = map[string]interface{}{
		"{{randstr}}": "2eNU2kbrOcUDzhnUL1RGvSo1it7",
	}

	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile network request")

	var finalEvent *output.InternalWrappedEvent
	var matchCount int
	t.Run("test", func(t *testing.T) {
		metadata := make(output.InternalEvent)
		previous := make(output.InternalEvent)
		ctxArgs := contextargs.NewWithInput(context.Background(), ts.URL)
		err := request.ExecuteWithResults(ctxArgs, metadata, previous, func(event *output.InternalWrappedEvent) {
			if event.OperatorsResult != nil && event.OperatorsResult.Matched {
				matchCount++
			}
			finalEvent = event
		})
		require.Nil(t, err, "could not execute network request")
	})
	require.NotNil(t, finalEvent, "could not get event output from request")
	require.Equal(t, 1, matchCount, "could not get correct match count")
	require.NotEmpty(t, finalEvent.Results[0].ReqURLPattern, "could not get req url pattern")
	require.Equal(t, `/{{rand_char("abc")}}/{{interactsh-url}}/123?query={{rand_int(1, 10)}}&data={{randstr}}`, finalEvent.Results[0].ReqURLPattern)
}

// fakeHostErrorsCache implements hosterrorscache.CacheInterface minimally for tests
type fakeHostErrorsCache struct{}

func (f *fakeHostErrorsCache) SetVerbose(bool)                                {}
func (f *fakeHostErrorsCache) Close()                                         {}
func (f *fakeHostErrorsCache) Remove(*contextargs.Context)                    {}
func (f *fakeHostErrorsCache) MarkFailed(string, *contextargs.Context, error) {}
func (f *fakeHostErrorsCache) MarkFailedOrRemove(string, *contextargs.Context, error) {
}

// Check always returns true to simulate an already unresponsive host
func (f *fakeHostErrorsCache) Check(string, *contextargs.Context) bool { return true }

// IsPermanentErr returns false for tests
func (f *fakeHostErrorsCache) IsPermanentErr(*contextargs.Context, error) bool { return false }

// spyHostErrorsCache records how the request path interacts with the cache:
// a mark (non-nil error) versus a reset (nil error). Check returns skip so the
// request actually executes.
type spyHostErrorsCache struct {
	marks  atomic.Int32
	resets atomic.Int32
	skip   bool
}

func (s *spyHostErrorsCache) SetVerbose(bool)             {}
func (s *spyHostErrorsCache) Close()                      {}
func (s *spyHostErrorsCache) Remove(*contextargs.Context) { s.resets.Add(1) }
func (s *spyHostErrorsCache) MarkFailed(p string, c *contextargs.Context, err error) {
	s.MarkFailedOrRemove(p, c, err)
}
func (s *spyHostErrorsCache) MarkFailedOrRemove(_ string, _ *contextargs.Context, err error) {
	if err == nil {
		s.resets.Add(1)
	} else {
		s.marks.Add(1)
	}
}
func (s *spyHostErrorsCache) Check(string, *contextargs.Context) bool         { return s.skip }
func (s *spyHostErrorsCache) IsPermanentErr(*contextargs.Context, error) bool { return false }

type addressSpyHostErrorsCache struct {
	mu     sync.Mutex
	checks []string
	resets []string
}

func (s *addressSpyHostErrorsCache) SetVerbose(bool) {}
func (s *addressSpyHostErrorsCache) Close()          {}
func (s *addressSpyHostErrorsCache) Remove(ctx *contextargs.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.resets = append(s.resets, ctx.MetaInput.Address())
}
func (s *addressSpyHostErrorsCache) MarkFailed(string, *contextargs.Context, error) {}
func (s *addressSpyHostErrorsCache) MarkFailedOrRemove(_ string, ctx *contextargs.Context, err error) {
	if err == nil {
		s.Remove(ctx)
	}
}
func (s *addressSpyHostErrorsCache) Check(_ string, ctx *contextargs.Context) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.checks = append(s.checks, ctx.MetaInput.Address())
	return false
}
func (s *addressSpyHostErrorsCache) IsPermanentErr(*contextargs.Context, error) bool {
	return false
}

func TestHTTPResetsHostCacheOnSuccess(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "ok")
	}))
	defer ts.Close()

	templateID := "reset-on-success"
	req := &Request{
		ID:     templateID,
		Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
		Path:   []string{"{{BaseURL}}/"},
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Part:  "body",
				Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
				Words: []string{"ok"},
			}},
		},
	}

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	spy := &spyHostErrorsCache{}
	executerOpts.HostErrorsCache = spy
	require.NoError(t, req.Compile(executerOpts))

	metadata := make(output.InternalEvent)
	previous := make(output.InternalEvent)
	ctxArgs := contextargs.NewWithInput(context.Background(), ts.URL)
	err := req.ExecuteWithResults(ctxArgs, metadata, previous, func(event *output.InternalWrappedEvent) {})
	require.NoError(t, err)

	require.Greater(t, spy.resets.Load(), int32(0), "a successful request must reset the host-errors cache")
	require.Equal(t, int32(0), spy.marks.Load(), "a successful request must not mark a host error")
}

func TestParallelHTTPResetsHostCacheOnSuccess(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "ok")
	}))
	defer ts.Close()

	templateID := "parallel-reset-on-success"
	req := &Request{
		ID:      templateID,
		Method:  HTTPMethodTypeHolder{MethodType: HTTPGet},
		Path:    []string{"{{BaseURL}}/p?x={{v}}"},
		Threads: 2,
		Payloads: map[string]interface{}{
			"v": []string{"1", "2", "3", "4"},
		},
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Part:  "body",
				Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
				Words: []string{"ok"},
			}},
		},
	}

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	spy := &spyHostErrorsCache{}
	executerOpts.HostErrorsCache = spy
	require.NoError(t, req.Compile(executerOpts))

	metadata := make(output.InternalEvent)
	previous := make(output.InternalEvent)
	ctxArgs := contextargs.NewWithInput(context.Background(), ts.URL)
	err := req.ExecuteWithResults(ctxArgs, metadata, previous, func(event *output.InternalWrappedEvent) {})
	require.NoError(t, err)

	require.Greater(t, spy.resets.Load(), int32(0), "successful parallel requests must reset the host-errors cache")
	require.Equal(t, int32(0), spy.marks.Load(), "successful parallel requests must not mark a host error")
}

func TestParallelHTTPResetsUpdatedHostCacheKeyOnSuccess(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "ok")
	}))
	defer ts.Close()

	templateID := "parallel-reset-updated-host"
	req := &Request{
		ID:      templateID,
		Method:  HTTPMethodTypeHolder{MethodType: HTTPGet},
		Path:    []string{ts.URL + "/p?x={{v}}"},
		Threads: 2,
		Payloads: map[string]interface{}{
			"v": []string{"1", "2"},
		},
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Part:  "body",
				Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
				Words: []string{"ok"},
			}},
		},
	}

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	spy := &addressSpyHostErrorsCache{}
	executerOpts.HostErrorsCache = spy
	require.NoError(t, req.Compile(executerOpts))

	metadata := make(output.InternalEvent)
	previous := make(output.InternalEvent)
	ctxArgs := contextargs.NewWithInput(context.Background(), "http://example.invalid")
	err := req.ExecuteWithResults(ctxArgs, metadata, previous, func(event *output.InternalWrappedEvent) {})
	require.NoError(t, err)

	expectedAddress := contextargs.NewWithInput(context.Background(), ts.URL).MetaInput.Address()
	require.Contains(t, spy.checks, expectedAddress, "generated request host must be checked")
	require.Contains(t, spy.resets, expectedAddress, "success must reset the generated request host")
}

func TestExecuteParallelHTTP_StopAtFirstMatch(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)

	// server that always matches
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "match")
	}))
	defer ts.Close()

	templateID := "parallel-stop-first"
	req := &Request{
		ID:      templateID,
		Method:  HTTPMethodTypeHolder{MethodType: HTTPGet},
		Path:    []string{"{{BaseURL}}/p?x={{v}}"},
		Threads: 2,
		Payloads: map[string]interface{}{
			"v": []string{"1", "2"},
		},
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Part:  "body",
				Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
				Words: []string{"match"},
			}},
		},
		StopAtFirstMatch: true,
	}

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := req.Compile(executerOpts)
	require.NoError(t, err)

	var matches int32
	metadata := make(output.InternalEvent)
	previous := make(output.InternalEvent)
	ctxArgs := contextargs.NewWithInput(context.Background(), ts.URL)
	err = req.ExecuteWithResults(ctxArgs, metadata, previous, func(event *output.InternalWrappedEvent) {
		if event.OperatorsResult != nil && event.OperatorsResult.Matched {
			atomic.AddInt32(&matches, 1)
		}
	})
	require.NoError(t, err)
	require.Equal(t, int32(1), atomic.LoadInt32(&matches), "expected only first match to be processed")
}

func TestExecuteParallelHTTP_StopAtFirstMatchCancelsQueuedRateLimitWaiters(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	options.ExecutionId = t.Name()
	options.PerHostRateLimit = true
	options.PerHostRateLimitPoolSize = -1
	options.RateLimit = 1
	options.RateLimitDuration = time.Second
	options.RestrictLocalNetworkAccess = false
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = fmt.Fprint(writer, "match")
	}))
	defer server.Close()

	request := &Request{
		ID:      "parallel-stop-first-rate-limit",
		Method:  HTTPMethodTypeHolder{MethodType: HTTPGet},
		Path:    []string{"{{BaseURL}}/p?x={{v}}"},
		Threads: 10,
		Payloads: map[string]interface{}{
			"v": []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"},
		},
		Operators: operators.Operators{Matchers: []*matchers.Matcher{{
			Part:  "body",
			Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Words: []string{"match"},
		}}},
		StopAtFirstMatch: true,
	}
	executerOptions := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   request.ID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	require.NoError(t, request.Compile(executerOptions))

	err := request.ExecuteWithResults(
		contextargs.NewWithInput(context.Background(), server.URL),
		make(output.InternalEvent),
		make(output.InternalEvent),
		func(*output.InternalWrappedEvent) {},
	)
	require.NoError(t, err)
	require.Equal(t, int32(1), requests.Load())
}

func TestExecuteParallelHTTP_SkipOnUnresponsiveFromCache(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)

	// server that would match if reached
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "match")
	}))
	defer ts.Close()

	templateID := "parallel-skip-unresponsive"
	req := &Request{
		ID:      templateID,
		Method:  HTTPMethodTypeHolder{MethodType: HTTPGet},
		Path:    []string{"{{BaseURL}}/p?x={{v}}"},
		Threads: 2,
		Payloads: map[string]interface{}{
			"v": []string{"1", "2"},
		},
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Part:  "body",
				Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
				Words: []string{"match"},
			}},
		},
	}

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	// inject fake host errors cache that forces skip
	executerOpts.HostErrorsCache = &fakeHostErrorsCache{}

	err := req.Compile(executerOpts)
	require.NoError(t, err)

	var matches int32
	metadata := make(output.InternalEvent)
	previous := make(output.InternalEvent)
	ctxArgs := contextargs.NewWithInput(context.Background(), ts.URL)
	err = req.ExecuteWithResults(ctxArgs, metadata, previous, func(event *output.InternalWrappedEvent) {
		if event.OperatorsResult != nil && event.OperatorsResult.Matched {
			atomic.AddInt32(&matches, 1)
		}
	})
	require.NoError(t, err)
	require.Equal(t, int32(0), atomic.LoadInt32(&matches), "expected no matches when host is marked unresponsive")
}

// TestExecuteParallelHTTP_GoroutineLeaks uses goleak to detect goroutine leaks in all HTTP parallel execution scenarios
func TestExecuteParallelHTTP_GoroutineLeaks(t *testing.T) {
	defer goleak.VerifyNone(t,
		goleak.IgnoreAnyContainingPkg("go.opencensus.io/stats/view"),
		goleak.IgnoreAnyContainingPkg("github.com/syndtr/goleveldb"),
		goleak.IgnoreAnyContainingPkg("github.com/go-rod/rod"),
		goleak.IgnoreAnyContainingPkg("github.com/projectdiscovery/interactsh/pkg/server"),
		goleak.IgnoreAnyContainingPkg("github.com/projectdiscovery/interactsh/pkg/client"),
		goleak.IgnoreAnyContainingPkg("github.com/projectdiscovery/ratelimit"),
		goleak.IgnoreAnyFunction("github.com/syndtr/goleveldb/leveldb/util.(*BufferPool).drain"),
		goleak.IgnoreAnyFunction("github.com/syndtr/goleveldb/leveldb.(*DB).compactionError"),
		goleak.IgnoreAnyFunction("github.com/syndtr/goleveldb/leveldb.(*DB).mpoolDrain"),
		goleak.IgnoreAnyFunction("github.com/syndtr/goleveldb/leveldb.(*DB).tCompaction"),
		goleak.IgnoreAnyFunction("github.com/syndtr/goleveldb/leveldb.(*DB).mCompaction"),
		// expirable LRU cache creates a background goroutine for TTL expiration that persists
		// see: https://github.com/hashicorp/golang-lru/blob/770151e9c8cdfae1797826b7b74c33d6f103fbd8/expirable/expirable_lru.go#L79
		goleak.IgnoreAnyContainingPkg("github.com/hashicorp/golang-lru/v2/expirable"),
		// net/http keep-alive connections spawn persistConn read/write loops that are
		// owned by the transport's idle-connection pool, not by the parallel executor.
		// They are torn down asynchronously on idle timeout, and on slower runners
		// (e.g. windows) that teardown can outlast goleak's retry window, so ignore them.
		goleak.IgnoreAnyFunction("net/http.(*persistConn).writeLoop"),
		goleak.IgnoreAnyFunction("net/http.(*persistConn).readLoop"),
	)

	options := testutils.DefaultOptions
	testutils.Init(options)
	defer testutils.Cleanup(options)

	// Test Case 1: Normal execution with StopAtFirstMatch
	t.Run("StopAtFirstMatch", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(10 * time.Millisecond)
			_, _ = fmt.Fprintf(w, "test response")
		}))
		defer ts.Close()

		req := &Request{
			ID:      "parallel-stop-first-match",
			Method:  HTTPMethodTypeHolder{MethodType: HTTPGet},
			Path:    []string{"{{BaseURL}}/test?param={{payload}}"},
			Threads: 4,
			Payloads: map[string]interface{}{
				"payload": []string{"1", "2", "3", "4", "5", "6", "7", "8"},
			},
			Operators: operators.Operators{
				Matchers: []*matchers.Matcher{{
					Part:  "body",
					Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
					Words: []string{"test response"},
				}},
			},
			StopAtFirstMatch: true,
		}

		executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
			ID:   "parallel-stop-first-match",
			Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
		})

		err := req.Compile(executerOpts)
		require.NoError(t, err)

		metadata := make(output.InternalEvent)
		previous := make(output.InternalEvent)
		ctxArgs := contextargs.NewWithInput(context.Background(), ts.URL)

		err = req.ExecuteWithResults(ctxArgs, metadata, previous, func(event *output.InternalWrappedEvent) {})
		require.NoError(t, err)
	})

	// Test Case 2: Unresponsive host scenario
	t.Run("UnresponsiveHost", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprintf(w, "response")
		}))
		defer ts.Close()

		req := &Request{
			ID:      "parallel-unresponsive",
			Method:  HTTPMethodTypeHolder{MethodType: HTTPGet},
			Path:    []string{"{{BaseURL}}/test?param={{payload}}"},
			Threads: 3,
			Payloads: map[string]interface{}{
				"payload": []string{"1", "2", "3", "4", "5"},
			},
			Operators: operators.Operators{
				Matchers: []*matchers.Matcher{{
					Part:  "body",
					Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
					Words: []string{"response"},
				}},
			},
		}

		executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
			ID:   "parallel-unresponsive",
			Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
		})
		executerOpts.HostErrorsCache = &fakeHostErrorsCache{}

		err := req.Compile(executerOpts)
		require.NoError(t, err)

		metadata := make(output.InternalEvent)
		previous := make(output.InternalEvent)
		ctxArgs := contextargs.NewWithInput(context.Background(), ts.URL)

		err = req.ExecuteWithResults(ctxArgs, metadata, previous, func(event *output.InternalWrappedEvent) {})
		require.NoError(t, err)
	})

	// Test Case 3: Context cancellation scenario
	t.Run("ContextCancellation", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(200 * time.Millisecond)
			_, _ = fmt.Fprintf(w, "response")
		}))
		defer ts.Close()

		req := &Request{
			ID:      "parallel-context-cancel",
			Method:  HTTPMethodTypeHolder{MethodType: HTTPGet},
			Path:    []string{"{{BaseURL}}/test?param={{payload}}"},
			Threads: 3,
			Payloads: map[string]interface{}{
				"payload": []string{"1", "2", "3", "4", "5"},
			},
			Operators: operators.Operators{
				Matchers: []*matchers.Matcher{{
					Part:  "body",
					Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
					Words: []string{"response"},
				}},
			},
		}

		executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
			ID:   "parallel-context-cancel",
			Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
		})

		err := req.Compile(executerOpts)
		require.NoError(t, err)

		metadata := make(output.InternalEvent)
		previous := make(output.InternalEvent)

		ctx, cancel := context.WithCancel(context.Background())
		ctxArgs := contextargs.NewWithInput(ctx, ts.URL)

		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		err = req.ExecuteWithResults(ctxArgs, metadata, previous, func(event *output.InternalWrappedEvent) {})
		require.Error(t, err)
		require.Equal(t, context.Canceled, err)
	})
}

func TestPerHostRateLimitHonorsRequestContextCancellation(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	options.ExecutionId = t.Name()
	options.PerHostRateLimit = true
	options.PerHostRateLimitPoolSize = -1
	options.RateLimit = 1
	options.RateLimitDuration = 2 * time.Second
	options.RestrictLocalNetworkAccess = false
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(writer, "ok")
	}))
	defer server.Close()

	request := &Request{
		ID:     "per-host-rate-limit-cancellation",
		Method: HTTPMethodTypeHolder{MethodType: HTTPGet},
		Path:   []string{"{{BaseURL}}/"},
		Operators: operators.Operators{Matchers: []*matchers.Matcher{{
			Part:  "body",
			Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Words: []string{"ok"},
		}}},
	}
	executerOptions := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   request.ID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	require.NoError(t, request.Compile(executerOptions))

	execute := func(ctx context.Context) error {
		return request.ExecuteWithResults(
			contextargs.NewWithInput(ctx, server.URL),
			make(output.InternalEvent),
			make(output.InternalEvent),
			func(*output.InternalWrappedEvent) {},
		)
	}
	require.NoError(t, execute(context.Background()))

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- execute(ctx) }()
	time.Sleep(100 * time.Millisecond)
	cancelledAt := time.Now()
	cancel()

	err := <-result
	cancellationDelay := time.Since(cancelledAt)
	t.Logf("request returned %s after its context was cancelled", cancellationDelay.Round(time.Millisecond))
	require.ErrorIs(t, err, context.Canceled)
	require.Less(t, cancellationDelay, 250*time.Millisecond)
}

func TestDumpedRequestKeepsBodyServerDidNotRead(t *testing.T) {
	// The server answers in full, then holds the connection without reading
	// the body, so the transport is still writing it when the response arrives.
	release := make(chan struct{})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "2")
		_, _ = w.Write([]byte("ok"))
		w.(http.Flusher).Flush()
		<-release
	}))
	defer target.Close()
	defer close(release)

	options := testutils.DefaultOptions.Copy()
	options.SetExecutionID(t.Name())
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "dump-body",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})

	body := strings.Repeat("A", 4<<20)
	requests := []*Request{
		{
			ID:     "post",
			Method: HTTPMethodTypeHolder{MethodType: HTTPPost},
			Path:   []string{"{{BaseURL}}/"},
			Body:   body,
		},
		{
			ID:  "get",
			Raw: []string{"GET / HTTP/1.1\nHost: {{Hostname}}\n\n" + body},
		},
		{
			ID:  "chunked",
			Raw: []string{"POST / HTTP/1.1\nHost: {{Hostname}}\nTransfer-Encoding: chunked\n\n" + body},
		},
	}
	for _, request := range requests {
		require.NoError(t, request.Compile(executerOpts))
		// how much the transport has written when the response lands varies, so
		// a few rounds make a lost body show up reliably
		for range 3 {
			var dumped string
			input := contextargs.NewWithInput(context.Background(), target.URL)
			err := request.ExecuteWithResults(input, output.InternalEvent{}, output.InternalEvent{}, func(event *output.InternalWrappedEvent) {
				dumped, _ = event.InternalEvent["request"].(string)
			})
			require.NoError(t, err)
			require.True(t, strings.HasSuffix(dumped, "\r\n\r\n"+body), "%s recorded request lost its body: %d of %d bytes", request.ID, len(dumped), len(body))
		}
	}
}

func TestReuseRequestBodyKeepsExcludedEncoding(t *testing.T) {
	body := []byte("original")
	for _, tc := range []struct {
		name          string
		method        string
		header        string
		contentLength int64
		wantLength    int64
	}{
		{name: "post", method: http.MethodPost, contentLength: 1, wantLength: int64(len(body))},
		{name: "get", method: http.MethodGet, contentLength: 3, wantLength: 3},
		{name: "head", method: http.MethodHead, contentLength: 0, wantLength: 0},
		{name: "chunked", method: http.MethodPost, header: "chunked", contentLength: -1, wantLength: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := retryablehttp.NewRequest(tc.method, "https://example.com/", body)
			require.NoError(t, err)
			req.ContentLength = tc.contentLength
			if tc.header != "" {
				req.Header.Set("Transfer-Encoding", tc.header)
			}

			require.NoError(t, reuseRequestBody(req))
			require.Equal(t, tc.wantLength, req.ContentLength)
			if tc.header != "" {
				require.Equal(t, tc.header, req.Header.Get("Transfer-Encoding"))
			}

			got, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			require.Equal(t, body, got)
			fresh, err := req.GetBody()
			require.NoError(t, err)
			got, err = io.ReadAll(fresh)
			require.NoError(t, err)
			require.Equal(t, body, got)
		})
	}
}
