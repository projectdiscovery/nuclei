package http

import (
	"context"
	"crypto/md5"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	operatorpkg "github.com/projectdiscovery/nuclei/v3/pkg/operators"
	extractorpkg "github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	matcherpkg "github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/utils/memguardian"
)

func TestIndexedResponsePayloadCannotUseIndependentRequestThreads(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	options.ExecutionId = t.Name()
	options.RestrictLocalNetworkAccess = false
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.URL.Path == "/first" {
			writer.WriteHeader(http.StatusCreated)
			return
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	request := &Request{
		ID: "indexed-response-payload-threading",
		Raw: []string{
			"GET /first?probe={{probe}} HTTP/1.1\nHost: {{Hostname}}",
			"GET /second?probe={{probe}} HTTP/1.1\nHost: {{Hostname}}",
		},
		Threads:  10,
		Payloads: map[string]interface{}{"probe": []string{"one", "two"}},
		Operators: operatorsWithMatchers(&matcherpkg.Matcher{
			Type: matcherpkg.MatcherTypeHolder{MatcherType: matcherpkg.DSLMatcher},
			DSL:  []string{"status_code_1 == 201 && status_code_2 == 200"},
		}),
	}
	executerOptions := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   request.ID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	executerOptions.RateLimiter = nil
	require.NoError(t, request.Compile(executerOptions))
	require.Zero(t, request.Threads)

	run := func() int {
		matched := 0
		err := request.ExecuteWithResults(
			contextargs.NewWithInput(t.Context(), server.URL),
			make(output.InternalEvent),
			make(output.InternalEvent),
			func(event *output.InternalWrappedEvent) {
				if event.OperatorsResult != nil && event.OperatorsResult.Matched {
					matched++
				}
			},
		)
		require.NoError(t, err)
		return matched
	}

	require.Equal(t, 2, run())
	require.Equal(t, int32(4), requests.Load())

	request.Threads = 10
	requests.Store(0)
	require.Zero(t, run())
	require.Equal(t, int32(4), requests.Load())
}

func TestDependentPayloadThreadsRejectSharedRequestState(t *testing.T) {
	newRequest := func() *Request {
		return &Request{Raw: []string{
			"GET /first HTTP/1.1\nHost: {{Hostname}}",
			"GET /second HTTP/1.1\nHost: {{Hostname}}",
		}}
	}

	base := newRequest()
	require.True(t, base.canRunDependentPayloadsConcurrently())

	iterating := newRequest()
	iterating.IterateAll = true
	require.False(t, iterating.canRunDependentPayloadsConcurrently())

	racing := newRequest()
	racing.Race = true
	require.False(t, racing.canRunDependentPayloadsConcurrently())

	pipelined := newRequest()
	pipelined.Pipeline = true
	require.False(t, pipelined.canRunDependentPayloadsConcurrently())

	once := newRequest()
	once.Raw[0] = "@once\n" + once.Raw[0]
	require.False(t, once.canRunDependentPayloadsConcurrently())
}

func TestIndexedResponsePayloadThreadsKeepPairsOrdered(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	options.ExecutionId = t.Name()
	options.RestrictLocalNetworkAccess = false
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	require.NotNil(t, memguardian.DefaultMemGuardian)
	previousWarning := memguardian.DefaultMemGuardian.Warning.Swap(false)
	t.Cleanup(func() { memguardian.DefaultMemGuardian.Warning.Store(previousWarning) })

	var firstStarted atomic.Int32
	var firstActive atomic.Int32
	var maximumFirstActive atomic.Int32
	var outOfOrder atomic.Int32
	firstGate := make(chan struct{})
	firstDone := make(map[string]bool)
	var firstDoneMu sync.Mutex
	negativeProbe := fmt.Sprintf("%x", md5.Sum([]byte("two")))
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		probe := request.URL.Query().Get("probe")
		switch request.URL.Path {
		case "/first":
			active := firstActive.Add(1)
			for old := maximumFirstActive.Load(); active > old && !maximumFirstActive.CompareAndSwap(old, active); old = maximumFirstActive.Load() {
			}
			if firstStarted.Add(1) == 2 {
				close(firstGate)
			}
			select {
			case <-firstGate:
			case <-time.After(250 * time.Millisecond):
			}
			firstDoneMu.Lock()
			firstDone[probe] = true
			firstDoneMu.Unlock()
			firstActive.Add(-1)
			writer.WriteHeader(http.StatusCreated)
		case "/second":
			firstDoneMu.Lock()
			if !firstDone[probe] {
				outOfOrder.Add(1)
			}
			firstDoneMu.Unlock()
			if probe == negativeProbe {
				writer.WriteHeader(http.StatusNotFound)
				return
			}
			writer.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	request := &Request{
		ID: "indexed-response-payload-pairs",
		Raw: []string{
			"GET /first?probe={{md5(probe)}} HTTP/1.1\nHost: {{Hostname}}",
			"GET /second?probe={{md5(probe)}} HTTP/1.1\nHost: {{Hostname}}",
		},
		PayloadThreads: 2,
		Payloads:       map[string]interface{}{"probe": []string{"one", "two"}},
		Operators: operatorsWithMatchers(&matcherpkg.Matcher{
			Type: matcherpkg.MatcherTypeHolder{MatcherType: matcherpkg.DSLMatcher},
			DSL:  []string{"status_code_1 == 201 && status_code_2 == 200"},
		}),
	}
	executerOptions := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   request.ID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	executerOptions.RateLimiter = nil
	require.NoError(t, request.Compile(executerOptions))

	var matches atomic.Int32
	require.NoError(t, request.ExecuteWithResults(
		contextargs.NewWithInput(t.Context(), server.URL),
		make(output.InternalEvent),
		make(output.InternalEvent),
		func(event *output.InternalWrappedEvent) {
			if event.OperatorsResult != nil && event.OperatorsResult.Matched {
				matches.Add(1)
			}
		},
	))
	require.Equal(t, int32(1), matches.Load())
	require.Zero(t, outOfOrder.Load())
	require.Equal(t, int32(2), maximumFirstActive.Load())
	require.Len(t, firstDone, 2)
}

func TestIndexedResponsePayloadThreadsStopAfterFirstMatch(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	options.ExecutionId = t.Name()
	options.RestrictLocalNetworkAccess = false
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	require.NotNil(t, memguardian.DefaultMemGuardian)
	previousWarning := memguardian.DefaultMemGuardian.Warning.Swap(false)
	t.Cleanup(func() { memguardian.DefaultMemGuardian.Warning.Store(previousWarning) })

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.URL.Path == "/first" {
			writer.WriteHeader(http.StatusCreated)
			return
		}
		if request.URL.Query().Get("probe") == "match" {
			writer.WriteHeader(http.StatusOK)
			return
		}
		writer.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	request := &Request{
		ID: "indexed-response-stop-first-match",
		Raw: []string{
			"GET /first?probe={{probe}} HTTP/1.1\nHost: {{Hostname}}",
			"GET /second?probe={{probe}} HTTP/1.1\nHost: {{Hostname}}",
		},
		PayloadThreads:   2,
		StopAtFirstMatch: true,
		Payloads: map[string]interface{}{
			"probe": []string{"match", "miss-a", "miss-b", "miss-c"},
		},
		Operators: operatorsWithMatchers(&matcherpkg.Matcher{
			Type: matcherpkg.MatcherTypeHolder{MatcherType: matcherpkg.DSLMatcher},
			DSL:  []string{"status_code_1 == 201 && status_code_2 == 200"},
		}),
	}
	executerOptions := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   request.ID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	executerOptions.RateLimiter = nil
	progressCounter := &payloadRequestProgress{Progress: executerOptions.Progress}
	executerOptions.Progress = progressCounter
	require.NoError(t, request.Compile(executerOptions))

	var matches atomic.Int32
	require.NoError(t, request.ExecuteWithResults(
		contextargs.NewWithInput(t.Context(), server.URL),
		make(output.InternalEvent),
		make(output.InternalEvent),
		func(event *output.InternalWrappedEvent) {
			if event.OperatorsResult != nil && event.OperatorsResult.Matched {
				matches.Add(1)
			}
		},
	))
	require.Equal(t, int32(1), matches.Load())
	require.Less(t, requests.Load(), int32(8))
	require.Equal(t, int64(request.Requests()), progressCounter.sent.Load()+progressCounter.skipped.Load()+progressCounter.failed.Load())
	require.Zero(t, progressCounter.failed.Load())
}

func TestIndexedResponsePayloadThreadsCoverAllFiveHundredResponses(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	options.ExecutionId = t.Name()
	options.RestrictLocalNetworkAccess = false
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	require.NotNil(t, memguardian.DefaultMemGuardian)
	previousWarning := memguardian.DefaultMemGuardian.Warning.Swap(false)
	t.Cleanup(func() { memguardian.DefaultMemGuardian.Warning.Store(previousWarning) })

	var active atomic.Int32
	var maximum atomic.Int32
	var served atomic.Int32
	var keysMu sync.Mutex
	keys := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		current := active.Add(1)
		for old := maximum.Load(); current > old && !maximum.CompareAndSwap(old, current); old = maximum.Load() {
		}
		key := strings.SplitN(request.URL.RawQuery, "=", 2)[0]
		keysMu.Lock()
		keys[key]++
		keysMu.Unlock()
		time.Sleep(5 * time.Millisecond)
		active.Add(-1)
		served.Add(1)
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	buckets := make([]string, 17)
	for i := range buckets {
		buckets[i] = fmt.Sprintf("bucket-%d", i)
	}
	for _, tc := range []struct {
		name           string
		payloadThreads int
		minimumActive  int32
		maximumActive  int32
		lowMemory      bool
	}{
		{name: "serial", minimumActive: 1, maximumActive: 1},
		{name: "guarded", payloadThreads: 10, minimumActive: 1, maximumActive: 2, lowMemory: true},
		{name: "grouped", payloadThreads: 10, minimumActive: 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			memguardian.DefaultMemGuardian.Warning.Store(tc.lowMemory)
			maximum.Store(0)
			served.Store(0)
			keysMu.Lock()
			clear(keys)
			keysMu.Unlock()
			request := &Request{
				ID: "indexed-response-5xx-coverage-" + tc.name,
				Raw: []string{
					"GET /first?{{rand}}-{{md5(escape)}}-{{bucket}}=x HTTP/1.1\nHost: {{Hostname}}",
					"GET /second?{{rand}}-{{md5(escape)}}-{{bucket}}=x HTTP/1.1\nHost: {{Hostname}}",
				},
				PayloadThreads: tc.payloadThreads,
				AttackType:     generators.AttackTypeHolder{Value: generators.ClusterBombAttack},
				Payloads: map[string]interface{}{
					"escape": []string{"\v", "\f", "\x1c", "\x1d", "\x1e", "\x1f"},
					"bucket": buckets,
				},
				Operators: operatorsWithMatchers(&matcherpkg.Matcher{
					Type: matcherpkg.MatcherTypeHolder{MatcherType: matcherpkg.DSLMatcher},
					DSL:  []string{"status_code_2 == 200"},
				}),
				StopAtFirstMatch: true,
			}
			executerOptions := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
				ID:   request.ID,
				Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
			})
			executerOptions.RateLimiter = nil
			require.NoError(t, executerOptions.Variables.UnmarshalJSON([]byte(`{"rand":"{{rand_base(5)}}"}`)))
			progressCounter := &payloadRequestProgress{Progress: executerOptions.Progress}
			executerOptions.Progress = progressCounter
			require.NoError(t, request.Compile(executerOptions))

			var matches atomic.Int32
			require.NoError(t, request.ExecuteWithResults(
				contextargs.NewWithInput(t.Context(), server.URL),
				make(output.InternalEvent),
				make(output.InternalEvent),
				func(event *output.InternalWrappedEvent) {
					if event.OperatorsResult != nil && event.OperatorsResult.Matched {
						matches.Add(1)
					}
				},
			))
			require.Zero(t, matches.Load())
			require.Equal(t, int32(204), served.Load())
			require.Equal(t, int64(204), progressCounter.sent.Load())
			require.Zero(t, progressCounter.skipped.Load())
			require.Zero(t, progressCounter.failed.Load())
			require.GreaterOrEqual(t, maximum.Load(), tc.minimumActive)
			if tc.maximumActive > 0 {
				require.LessOrEqual(t, maximum.Load(), tc.maximumActive)
			}
			keysMu.Lock()
			require.Len(t, keys, 102)
			for _, count := range keys {
				require.Equal(t, 2, count)
			}
			keysMu.Unlock()
		})
	}
}

func TestIndexedResponsePayloadThreadsPreserveCachePoisoningDetection(t *testing.T) {
	options := testutils.DefaultOptions.Copy()
	options.ExecutionId = t.Name()
	options.RestrictLocalNetworkAccess = false
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })
	require.NotNil(t, memguardian.DefaultMemGuardian)
	previousWarning := memguardian.DefaultMemGuardian.Warning.Swap(false)
	t.Cleanup(func() { memguardian.DefaultMemGuardian.Warning.Store(previousWarning) })

	var mu sync.Mutex
	cache := make(map[string]string)
	var served atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		served.Add(1)
		key := strings.SplitN(request.URL.RawQuery, "=", 2)[0]
		mu.Lock()
		defer mu.Unlock()
		if request.URL.Path == "/first" {
			if request.Header.Get("X-Bucket") == "positive" {
				cache[key] = "alert(document.domain)"
			}
			writer.WriteHeader(http.StatusBadGateway)
			return
		}
		if value, ok := cache[key]; ok {
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte(value))
			return
		}
		writer.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	request := &Request{
		ID: "indexed-response-cache-poisoning",
		Raw: []string{
			"GET /first?{{rand}}-{{md5(escape)}}-{{bucket}}=x HTTP/1.1\nHost: {{Hostname}}\nX-Bucket: {{bucket}}",
			"GET /second?{{rand}}-{{md5(escape)}}-{{bucket}}=x HTTP/1.1\nHost: {{Hostname}}",
		},
		PayloadThreads: 2,
		AttackType:     generators.AttackTypeHolder{Value: generators.ClusterBombAttack},
		Payloads: map[string]interface{}{
			"escape": []string{"\v"},
			"bucket": []string{"positive", "negative"},
		},
		Operators: operatorsWithMatchers(&matcherpkg.Matcher{
			Type: matcherpkg.MatcherTypeHolder{MatcherType: matcherpkg.DSLMatcher},
			DSL:  []string{`contains(body_2, "alert(document.domain)") && status_code_2 == 200`},
		}),
	}
	executerOptions := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   request.ID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	executerOptions.RateLimiter = nil
	require.NoError(t, executerOptions.Variables.UnmarshalJSON([]byte(`{"rand":"{{rand_base(5)}}"}`)))
	require.NoError(t, request.Compile(executerOptions))

	var matches atomic.Int32
	require.NoError(t, request.ExecuteWithResults(
		contextargs.NewWithInput(t.Context(), server.URL),
		make(output.InternalEvent),
		make(output.InternalEvent),
		func(event *output.InternalWrappedEvent) {
			if event.OperatorsResult != nil && event.OperatorsResult.Matched {
				matches.Add(1)
			}
		},
	))
	require.Equal(t, int32(4), served.Load())
	require.Equal(t, int32(1), matches.Load())
	require.Len(t, cache, 1)
}

type payloadRequestProgress struct {
	progress.Progress
	sent    atomic.Int64
	skipped atomic.Int64
	failed  atomic.Int64
}

func (p *payloadRequestProgress) IncrementRequests() {
	p.sent.Add(1)
	p.Progress.IncrementRequests()
}

func (p *payloadRequestProgress) SetRequests(count uint64) {
	p.skipped.Add(int64(count))
	p.Progress.SetRequests(count)
}

func (p *payloadRequestProgress) IncrementFailedRequestsBy(count int64) {
	p.failed.Add(count)
	p.Progress.IncrementFailedRequestsBy(count)
}

func TestNeedsRequestConditionDurationReferences(t *testing.T) {
	tests := []struct {
		name    string
		request *Request
		want    bool
	}{
		{
			name: "duration indexed matcher dsl",
			request: &Request{
				Operators: operatorsWithMatchers(&matcherpkg.Matcher{
					Type: matcherpkg.MatcherTypeHolder{MatcherType: matcherpkg.DSLMatcher},
					DSL:  []string{"duration_1 < 1"},
				}),
			},
			want: true,
		},
		{
			name: "duration indexed matcher part",
			request: &Request{
				Operators: operatorsWithMatchers(&matcherpkg.Matcher{
					Type: matcherpkg.MatcherTypeHolder{MatcherType: matcherpkg.WordsMatcher},
					Part: "duration_2",
				}),
			},
			want: true,
		},
		{
			name: "duration indexed extractor dsl",
			request: &Request{
				Operators: operatorsWithExtractors(&extractorpkg.Extractor{
					Type: extractorpkg.ExtractorTypeHolder{ExtractorType: extractorpkg.DSLExtractor},
					DSL:  []string{"duration_1"},
				}),
			},
			want: true,
		},
		{
			name: "deprecated req condition alone",
			request: &Request{
				ReqCondition: true,
			},
			want: false,
		},
		{
			name: "unsuffixed duration",
			request: &Request{
				Operators: operatorsWithMatchers(&matcherpkg.Matcher{
					Type: matcherpkg.MatcherTypeHolder{MatcherType: matcherpkg.DSLMatcher},
					DSL:  []string{"duration < 1"},
				}),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.request.NeedsRequestCondition())
		})
	}
}

func TestHTTPDurationRequestIDPrefixUsesID(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)

	request := &Request{
		ID:   "probe",
		Name: "display-name",
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "testing-http-prefix",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	executerOpts.IsMultiProtocol = true

	input := contextargs.NewWithInput(context.Background(), "http://example.com")
	executerOpts.AddTemplateVars(input.MetaInput, request.Type(), request.GetID(), output.InternalEvent{
		"duration":   float64(1),
		"duration_1": float64(0.5),
	})

	values := executerOpts.GetTemplateCtx(input.MetaInput).GetAll()
	require.Equal(t, float64(1), values["probe_duration"])
	require.Equal(t, float64(0.5), values["probe_duration_1"])
	require.NotContains(t, values, "display-name_duration")
}

func operatorsWithMatchers(matchers ...*matcherpkg.Matcher) operatorpkg.Operators {
	return operatorpkg.Operators{Matchers: matchers}
}

func operatorsWithExtractors(extractors ...*extractorpkg.Extractor) operatorpkg.Operators {
	return operatorpkg.Operators{Extractors: extractors}
}
