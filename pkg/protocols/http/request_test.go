package http

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tarunKoyalwar/goleak"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
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
