package interactsh

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/logrusorgru/aurora/v4"
	serverint "github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/frequency"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/require"
)

type requestRoutingWriter struct {
	writes atomic.Int32
}

func (*requestRoutingWriter) Close() {}
func (*requestRoutingWriter) Colorizer() *aurora.Aurora {
	return aurora.New(aurora.WithColors(false))
}
func (w *requestRoutingWriter) Write(*output.ResultEvent) error {
	w.writes.Add(1)
	return nil
}
func (*requestRoutingWriter) WriteFailure(*output.InternalWrappedEvent) error { return nil }
func (*requestRoutingWriter) Request(string, string, string, error)           {}
func (*requestRoutingWriter) RequestStatsLog(string, string)                  {}
func (*requestRoutingWriter) WriteStoreDebugData(string, string, string, string) {
}
func (w *requestRoutingWriter) ResultCount() int { return int(w.writes.Load()) }

type requestRoutingProgress struct{}

func (*requestRoutingProgress) Stop()                           {}
func (*requestRoutingProgress) Init(int64, int, int64)          {}
func (*requestRoutingProgress) AddToTotal(int64)                {}
func (*requestRoutingProgress) IncrementRequests()              {}
func (*requestRoutingProgress) SetRequests(uint64)              {}
func (*requestRoutingProgress) IncrementMatched()               {}
func (*requestRoutingProgress) IncrementErrorsBy(int64)         {}
func (*requestRoutingProgress) IncrementFailedRequestsBy(int64) {}

func TestProcessInteractionRoutesResultToRequestWriter(t *testing.T) {
	matcher := &matchers.Matcher{
		Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
		Part:  "interactsh_protocol",
		Words: []string{"dns"},
	}
	op := &operators.Operators{Matchers: []*matchers.Matcher{matcher}}
	require.NoError(t, op.Compile())

	baseWriter := &requestRoutingWriter{}
	requestWriter := &requestRoutingWriter{}

	client := &Client{options: DefaultOptions(baseWriter, nil, &requestRoutingProgress{})}
	client.initializeCaches()
	data := &RequestData{
		Event: &output.InternalWrappedEvent{InternalEvent: output.InternalEvent{
			templateIdAttribute: "scoped-oob",
			"host":              "example.com",
		}},
		Operators: op,
		MatchFunc: func(_ map[string]interface{}, _ *matchers.Matcher) (bool, []string) {
			return true, []string{"dns"}
		},
		ExtractFunc: func(map[string]interface{}, *extractors.Extractor) map[string]struct{} { return nil },
		MakeResultFunc: func(*output.InternalWrappedEvent) []*output.ResultEvent {
			return []*output.ResultEvent{{TemplateID: "scoped-oob", MatcherStatus: true}}
		},
		Output:   requestWriter,
		Progress: &requestRoutingProgress{},
	}

	matched := client.processInteractionForRequest(&serverint.Interaction{
		Protocol:      "dns",
		RawRequest:    "request",
		RawResponse:   "response",
		RemoteAddress: "127.0.0.1",
	}, data)

	require.True(t, matched)
	require.Equal(t, 1, requestWriter.ResultCount())
	require.Zero(t, baseWriter.ResultCount(), "a shared client must not route a delayed result to its base writer")
}

func TestProcessInteractionWithFrequencyTrackerAndNonFuzzRequest(t *testing.T) {
	matcher := &matchers.Matcher{
		Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
		Part:  "interactsh_protocol",
		Words: []string{"dns"},
	}
	op := &operators.Operators{Matchers: []*matchers.Matcher{matcher}}
	require.NoError(t, op.Compile())

	resultWriter := &requestRoutingWriter{}
	options := DefaultOptions(resultWriter, nil, &requestRoutingProgress{})
	options.FuzzParamsFrequency = frequency.New(10, 2)
	client := &Client{options: options}
	client.initializeCaches()
	data := &RequestData{
		Event: &output.InternalWrappedEvent{InternalEvent: output.InternalEvent{
			templateIdAttribute: "non-fuzz-oob",
			"host":              "example.com",
		}},
		Operators: op,
		MatchFunc: func(_ map[string]interface{}, _ *matchers.Matcher) (bool, []string) {
			return true, []string{"dns"}
		},
		ExtractFunc: func(map[string]interface{}, *extractors.Extractor) map[string]struct{} { return nil },
		MakeResultFunc: func(*output.InternalWrappedEvent) []*output.ResultEvent {
			return []*output.ResultEvent{{TemplateID: "non-fuzz-oob", MatcherStatus: true}}
		},
	}

	matched := client.processInteractionForRequest(&serverint.Interaction{Protocol: "dns"}, data)

	require.True(t, matched)
	require.Equal(t, 1, resultWriter.ResultCount())
}

func TestRequestScopeRemovesOnlyItsRegistrations(t *testing.T) {
	options := DefaultOptions(nil, nil, nil)
	options.CooldownPeriod = 0
	client, err := New(options)
	require.NoError(t, err)
	client.setHostname("oast.test")

	first := client.NewRequestScope()
	second := client.NewRequestScope()
	newData := func(scope *RequestScope) *RequestData {
		return &RequestData{
			Event: &output.InternalWrappedEvent{InternalEvent: output.InternalEvent{}},
			Scope: scope,
		}
	}
	client.RequestEvent([]string{"first.oast.test"}, newData(first))
	client.RequestEvent([]string{"second.oast.test"}, newData(second))
	require.True(t, client.requests.Has("first"))
	require.True(t, client.requests.Has("second"))

	first.Close()
	require.False(t, client.requests.Has("first"))
	require.True(t, client.requests.Has("second"), "closing one execution must not purge another execution")

	second.Close()
	require.False(t, client.requests.Has("second"))
}
func TestRequestScopeCloseWaitsForInFlightCallback(t *testing.T) {
	options := DefaultOptions(nil, nil, nil)
	options.CooldownPeriod = 0
	client, err := New(options)
	require.NoError(t, err)

	scope := client.NewRequestScope()
	require.True(t, scope.beginCallback())

	closed := make(chan struct{})
	go func() {
		scope.Close()
		close(closed)
	}()

	select {
	case <-closed:
		t.Fatal("scope closed before its admitted callback completed")
	case <-time.After(25 * time.Millisecond):
	}

	scope.endCallback()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("scope did not close after its admitted callback completed")
	}
	require.False(t, scope.beginCallback(), "a closed scope must reject later callbacks")
}

func TestHasMarkersDetectsInteractshSNIAnnotation(t *testing.T) {
	require.True(t, HasMarkers("@tls-sni: interactsh-url\nGET / HTTP/1.1"))
	require.True(t, HasMarkers("  @tls-sni: https://interactsh-url  \nGET / HTTP/1.1"))
	require.False(t, HasMarkers("@tls-sni: request.host\nGET / HTTP/1.1"))
}

func TestNilClientURLReturnsInitializationError(t *testing.T) {
	var client *Client
	_, err := client.URL()
	require.ErrorIs(t, err, ErrInteractshClientNotInitialized)
}
func TestProcessInteractionForRequestConcurrentEventUpdate(t *testing.T) {
	const (
		keyCount        = 4096
		expressionCount = 256
		mutationCount   = keyCount * 200
	)

	eventData := make(output.InternalEvent, keyCount+2)
	eventData[templateIdAttribute] = "test-template"
	eventData["host"] = "example.com"

	var expressionBuilder strings.Builder
	for i := 0; i < keyCount; i++ {
		key := fmt.Sprintf("key%d", i)
		eventData[key] = fmt.Sprintf("value%d", i)
		if i < expressionCount {
			expressionBuilder.WriteString("{{")
			expressionBuilder.WriteString(key)
			expressionBuilder.WriteString("}}")
		}
	}

	matcher := &matchers.Matcher{
		Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
		Words: []string{expressionBuilder.String()},
	}
	op := &operators.Operators{
		Matchers:          []*matchers.Matcher{matcher},
		MatchersCondition: "or",
	}
	require.NoError(t, op.Compile())

	var startWriter sync.Once
	writerStarted := make(chan struct{})
	requestData := &RequestData{
		Event:     &output.InternalWrappedEvent{InternalEvent: eventData},
		Operators: op,
		MatchFunc: func(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
			startWriter.Do(func() {
				close(writerStarted)
			})
			runtime.Gosched()
			return matcher.MatchWords("not-present-in-corpus", data)
		},
		ExtractFunc: func(map[string]interface{}, *extractors.Extractor) map[string]struct{} {
			return nil
		},
	}

	var writerWG sync.WaitGroup
	writerWG.Add(1)
	go func() {
		defer writerWG.Done()
		<-writerStarted
		for i := 0; i < mutationCount; i++ {
			key := fmt.Sprintf("key%d", i%keyCount)
			requestData.Event.Lock()
			requestData.Event.InternalEvent[key] = fmt.Sprintf("mutated-%d", i)
			if i%17 == 0 {
				delete(requestData.Event.InternalEvent, key)
				requestData.Event.InternalEvent[key] = fmt.Sprintf("mutated-%d", i)
			}
			requestData.Event.Unlock()
		}
	}()

	client := &Client{options: &Options{}}
	matched := client.processInteractionForRequest(&serverint.Interaction{
		Protocol:      "dns",
		RawRequest:    "request",
		RawResponse:   "response",
		RemoteAddress: "127.0.0.1",
	}, requestData)
	writerWG.Wait()

	require.False(t, matched)
}

func TestClientDefersCachesUntilInteractshUse(t *testing.T) {
	client, err := New(DefaultOptions(nil, nil, nil))
	require.NoError(t, err)

	require.Nil(t, client.requests)
	require.Nil(t, client.interactions)
	require.Nil(t, client.matchedTemplates)
	require.Nil(t, client.interactshURLs)

	require.False(t, client.Close())
	require.Nil(t, client.requests)
	require.Nil(t, client.interactions)
	require.Nil(t, client.matchedTemplates)
	require.Nil(t, client.interactshURLs)
}

func TestClientInitializesCachesOnceConcurrently(t *testing.T) {
	client, err := New(DefaultOptions(nil, nil, nil))
	require.NoError(t, err)

	const callers = 32
	var waitGroup sync.WaitGroup
	waitGroup.Add(callers)
	for range callers {
		go func() {
			defer waitGroup.Done()
			client.initializeCaches()
		}()
	}
	waitGroup.Wait()

	require.NotNil(t, client.requests)
	require.NotNil(t, client.interactions)
	require.NotNil(t, client.matchedTemplates)
	require.NotNil(t, client.interactshURLs)
}
