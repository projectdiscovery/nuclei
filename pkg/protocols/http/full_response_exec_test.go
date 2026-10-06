package http

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/globalmatchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

const execBody = "hello-body"

func TestExecuteBodyMatcherKeepsJSONResponse(t *testing.T) {
	opts := newExecOptions(nil)
	event := executeAgainstBody(t, opts, wordsMatcher("body", execBody))

	require.Empty(t, types.ToString(event.InternalEvent["response"]))
	require.True(t, event.OperatorsResult.Matched)
	rebuilt := assertRebuiltResult(t, event)
	require.Contains(t, rebuilt, execBody)
	require.Contains(t, rebuilt, "header-marker")

	parsed := writeResultJSON(t, event.Results[0], false)
	require.Equal(t, rebuilt, parsed["response"])

	omitted := writeResultJSON(t, event.Results[0], true)
	_, present := omitted["response"]
	require.False(t, present)
}

func TestExecuteMatchersThatDoNotReadResponse(t *testing.T) {
	cases := []struct {
		name    string
		matcher *matchers.Matcher
	}{
		{name: "header", matcher: wordsMatcher("header", "header-marker")},
		{name: "all", matcher: wordsMatcher("all", "header-marker")},
		{name: "status", matcher: &matchers.Matcher{
			Type:   matchers.MatcherTypeHolder{MatcherType: matchers.StatusMatcher},
			Status: []int{200},
		}},
		{name: "regex body", matcher: &matchers.Matcher{
			Part:  "body",
			Type:  matchers.MatcherTypeHolder{MatcherType: matchers.RegexMatcher},
			Regex: []string{`hello-[a-z]+`},
		}},
		{name: "dsl body", matcher: &matchers.Matcher{
			Type: matchers.MatcherTypeHolder{MatcherType: matchers.DSLMatcher},
			DSL:  []string{`contains(body, "hello-body") && contains(all_headers, "header-marker")`},
		}},
		{name: "negative body", matcher: &matchers.Matcher{
			Part:     "body",
			Type:     matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Negative: true,
			Words:    []string{"missing-token"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			event := executeAgainstBody(t, newExecOptions(nil), tc.matcher)
			require.Empty(t, types.ToString(event.InternalEvent["response"]))
			require.True(t, event.OperatorsResult.Matched)
			require.Contains(t, assertRebuiltResult(t, event), execBody)
		})
	}
}

func TestExecuteExtractorOnBodyLeavesResponseEmpty(t *testing.T) {
	event := executeAgainstBody(t, newExecOptions(nil), wordsMatcher("body", execBody), &extractors.Extractor{
		Part:  "body",
		Name:  "tok",
		Type:  extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor},
		Regex: []string{`hello-[a-z]+`},
	})
	require.Empty(t, types.ToString(event.InternalEvent["response"]))
	require.True(t, event.OperatorsResult.Matched)
	require.Contains(t, event.OperatorsResult.OutputExtracts, execBody)
	require.Contains(t, assertRebuiltResult(t, event), execBody)
}

func TestExecuteBuildsResponseWhenOperatorsReadIt(t *testing.T) {
	cases := []struct {
		name    string
		matcher *matchers.Matcher
	}{
		{name: "part response", matcher: wordsMatcher("response", execBody)},
		{name: "dsl response", matcher: &matchers.Matcher{
			Type: matchers.MatcherTypeHolder{MatcherType: matchers.DSLMatcher},
			DSL:  []string{`contains(response, "hello-body")`},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			event := executeAgainstBody(t, newExecOptions(nil), tc.matcher)
			full := types.ToString(event.InternalEvent["response"])
			require.Contains(t, full, execBody)
			require.Contains(t, full, "header-marker")
			require.Equal(t, types.ToString(event.InternalEvent["all_headers"])+types.ToString(event.InternalEvent["body"]), full)
			require.True(t, event.OperatorsResult.Matched)
			require.Equal(t, full, assertRebuiltResult(t, event))
		})
	}
}

func TestExecuteExportsFullResponseForLaterSteps(t *testing.T) {
	t.Run("flow without id", func(t *testing.T) {
		opts := newExecOptions(nil)
		opts.Flow = "http()"
		input, event := executeAgainstBodyInput(t, opts, &Request{}, wordsMatcher("body", execBody))
		full := types.ToString(event.InternalEvent["response"])
		require.Contains(t, full, execBody)
		exported, ok := opts.GetTemplateCtx(input.MetaInput).Get("http_response")
		require.True(t, ok)
		require.Equal(t, full, types.ToString(exported))
	})

	t.Run("multi request with id", func(t *testing.T) {
		opts := newExecOptions(nil)
		opts.IsMultiProtocol = true
		input, event := executeAgainstBodyInput(t, opts, &Request{ID: "login"}, wordsMatcher("body", execBody))
		full := types.ToString(event.InternalEvent["response"])
		require.Contains(t, full, execBody)
		exported, ok := opts.GetTemplateCtx(input.MetaInput).Get("login_response")
		require.True(t, ok)
		require.Equal(t, full, types.ToString(exported))
		_, hasProtocolKey := opts.GetTemplateCtx(input.MetaInput).Get("http_response")
		require.False(t, hasProtocolKey)
	})
}

func TestExecuteRequestConditionHistory(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/first":
			_, _ = io.WriteString(w, "first-body")
		default:
			_, _ = io.WriteString(w, "second-body")
		}
	}))
	t.Cleanup(ts.Close)

	t.Run("body history does not keep response", func(t *testing.T) {
		events := executeRaw(t, newExecOptions(nil), ts.URL, wordsMatcher("body_1", "first-body"))
		var matched *output.InternalWrappedEvent
		for _, event := range events {
			if event.OperatorsResult != nil && event.OperatorsResult.Matched {
				matched = event
			}
		}
		require.NotNil(t, matched)
		require.Empty(t, types.ToString(matched.InternalEvent["response"]))
		require.Empty(t, types.ToString(matched.InternalEvent["response_1"]))
		require.Contains(t, types.ToString(matched.InternalEvent["body_1"]), "first-body")
		// The saved response is this event's own headers and body. body_1 is the earlier one.
		require.Contains(t, assertRebuiltResult(t, matched), types.ToString(matched.InternalEvent["body"]))
	})

	t.Run("response history is the full copy", func(t *testing.T) {
		events := executeRaw(t, newExecOptions(nil), ts.URL, wordsMatcher("response_1", "first-body"))
		var matched *output.InternalWrappedEvent
		for _, event := range events {
			if event.OperatorsResult != nil && event.OperatorsResult.Matched {
				matched = event
			}
		}
		require.NotNil(t, matched)
		history := types.ToString(matched.InternalEvent["response_1"])
		require.Contains(t, history, "first-body")
		require.Contains(t, history, "HTTP/1.1")
		require.NotEmpty(t, types.ToString(matched.InternalEvent["response"]))
	})
}

func TestExecuteOptionForcesFullResponse(t *testing.T) {
	for _, name := range []string{"debug", "store", "vardump"} {
		t.Run(name, func(t *testing.T) {
			opts := newExecOptions(func(options *types.Options) {
				switch name {
				case "debug":
					options.Debug = true
				case "store":
					options.StoreResponse = true
				case "vardump":
					options.ShowVarDump = true
				}
			})
			event := executeAgainstBody(t, opts, wordsMatcher("body", execBody))
			require.Contains(t, types.ToString(event.InternalEvent["response"]), execBody)
			require.True(t, event.OperatorsResult.Matched)
		})
	}
}

func TestExecuteGlobalMatcher(t *testing.T) {
	t.Run("body global matcher", func(t *testing.T) {
		opts := newExecOptions(nil)
		opts.GlobalMatchers = globalMatcher(t, wordsMatcher("body", execBody))
		event := executeAgainstBody(t, opts, nil)
		require.Empty(t, types.ToString(event.InternalEvent["response"]))
		require.True(t, event.OperatorsResult.Matched)
		require.Contains(t, assertRebuiltResult(t, event), execBody)
	})

	t.Run("response global matcher", func(t *testing.T) {
		opts := newExecOptions(nil)
		opts.GlobalMatchers = globalMatcher(t, wordsMatcher("response", execBody))
		event := executeAgainstBody(t, opts, nil)
		require.Contains(t, types.ToString(event.InternalEvent["response"]), execBody)
		require.True(t, event.OperatorsResult.Matched)
	})
}

func newExecOptions(mutate func(*types.Options)) *protocols.ExecutorOptions {
	options := *testutils.DefaultOptions
	options.ResponseSaveSize = 1 << 20
	if mutate != nil {
		mutate(&options)
	}
	testutils.Init(&options)
	return testutils.NewMockExecuterOptions(&options, &testutils.TemplateInfo{
		ID:   "full-response",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "full response"},
	})
}

func wordsMatcher(part, word string) *matchers.Matcher {
	return &matchers.Matcher{
		Part:  part,
		Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
		Words: []string{word},
	}
}

func globalMatcher(t *testing.T, matcher *matchers.Matcher) *globalmatchers.Storage {
	t.Helper()
	operator := &operators.Operators{Matchers: []*matchers.Matcher{matcher}}
	require.NoError(t, operator.Compile())
	storage := globalmatchers.New()
	storage.AddOperator(&globalmatchers.Item{
		TemplateID: "global",
		Operators:  []*operators.Operators{operator},
	})
	return storage
}

func executeAgainstBody(t *testing.T, opts *protocols.ExecutorOptions, matcher *matchers.Matcher, extra ...*extractors.Extractor) *output.InternalWrappedEvent {
	t.Helper()
	_, event := executeAgainstBodyInput(t, opts, &Request{}, matcher, extra...)
	return event
}

func executeAgainstBodyInput(t *testing.T, opts *protocols.ExecutorOptions, request *Request, matcher *matchers.Matcher, extra ...*extractors.Extractor) (*contextargs.Context, *output.InternalWrappedEvent) {
	t.Helper()
	request.Method = HTTPMethodTypeHolder{MethodType: HTTPGet}
	request.Path = []string{"{{BaseURL}}"}
	if matcher != nil {
		request.Matchers = []*matchers.Matcher{matcher}
	}
	request.Extractors = append(request.Extractors, extra...)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Marker", "header-marker")
		_, _ = io.WriteString(w, execBody)
	}))
	t.Cleanup(ts.Close)

	require.NoError(t, request.Compile(opts))
	input := contextargs.NewWithInput(context.Background(), ts.URL)
	var matched *output.InternalWrappedEvent
	err := request.ExecuteWithResults(input, make(output.InternalEvent), make(output.InternalEvent), func(event *output.InternalWrappedEvent) {
		if event != nil && event.OperatorsResult != nil && event.OperatorsResult.Matched {
			matched = event
		}
	})
	require.NoError(t, err)
	require.NotNil(t, matched)
	return input, matched
}

func executeRaw(t *testing.T, opts *protocols.ExecutorOptions, rawURL string, matcher *matchers.Matcher) []*output.InternalWrappedEvent {
	t.Helper()
	request := &Request{
		Raw: []string{
			"GET /first HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
			"GET /second HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n",
		},
		Operators: operators.Operators{Matchers: []*matchers.Matcher{matcher}},
	}
	require.NoError(t, request.Compile(opts))
	input := contextargs.NewWithInput(context.Background(), rawURL)
	var events []*output.InternalWrappedEvent
	err := request.ExecuteWithResults(input, make(output.InternalEvent), make(output.InternalEvent), func(event *output.InternalWrappedEvent) {
		events = append(events, event)
	})
	require.NoError(t, err)
	require.NotEmpty(t, events)
	return events
}

func assertRebuiltResult(t *testing.T, event *output.InternalWrappedEvent) string {
	t.Helper()
	require.NotEmpty(t, event.Results)
	response := event.Results[0].Response
	require.Equal(t, types.ToString(event.InternalEvent["all_headers"])+types.ToString(event.InternalEvent["body"]), response)
	return response
}

func writeResultJSON(t *testing.T, event *output.ResultEvent, omitRaw bool) map[string]any {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/out.jsonl"
	writer, err := output.NewStandardWriter(&types.Options{
		JSONL:            true,
		OmitRawRequests:  omitRaw,
		Output:           path,
		ResponseSaveSize: 1 << 20,
	})
	require.NoError(t, err)
	writer.DisableStdout = true
	require.NoError(t, writer.Write(event))
	writer.Close()

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(data, &parsed))
	return parsed
}
