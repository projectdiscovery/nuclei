package http

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/globalmatchers"
)

func TestNeedsFullResponse(t *testing.T) {
	t.Run("body status and header do not", func(t *testing.T) {
		request := &Request{
			Operators: operators.Operators{
				Matchers: []*matchers.Matcher{
					{Part: "body"},
					{Part: "status"},
					{Part: "header"},
					{},
				},
				Extractors: []*extractors.Extractor{
					{Part: "body"},
				},
			},
		}
		require.False(t, request.needsFullResponse())
	})

	for _, part := range []string{"response", "response_1", "all"} {
		t.Run(part, func(t *testing.T) {
			request := &Request{Operators: operators.Operators{
				Matchers: []*matchers.Matcher{{Part: part}},
			}}
			require.True(t, request.needsFullResponse())
		})
	}

	t.Run("dsl mentioning response", func(t *testing.T) {
		request := &Request{Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{DSL: []string{`contains(tolower(response), "token")`}}},
		}}
		require.True(t, request.needsFullResponse())
	})

	t.Run("extractor part response", func(t *testing.T) {
		request := &Request{Operators: operators.Operators{
			Extractors: []*extractors.Extractor{{Part: "response"}},
		}}
		require.True(t, request.needsFullResponse())
	})

	t.Run("compiled operators", func(t *testing.T) {
		request := &Request{CompiledOperators: &operators.Operators{
			Matchers: []*matchers.Matcher{{Part: "response_2"}},
		}}
		require.True(t, request.needsFullResponse())
	})

	t.Run("global matcher that reads response", func(t *testing.T) {
		storage := globalmatchers.New()
		storage.AddOperator(&globalmatchers.Item{
			Operators: []*operators.Operators{{
				Matchers: []*matchers.Matcher{{Part: "response"}},
			}},
		})
		request := &Request{
			Operators: operators.Operators{Matchers: []*matchers.Matcher{{Part: "body"}}},
			options:   &protocols.ExecutorOptions{GlobalMatchers: storage},
		}
		require.True(t, request.needsFullResponse())
	})

	t.Run("global matcher on body does not", func(t *testing.T) {
		storage := globalmatchers.New()
		storage.AddOperator(&globalmatchers.Item{
			Operators: []*operators.Operators{{
				Matchers: []*matchers.Matcher{{Part: "body"}},
			}},
		})
		request := &Request{
			options: &protocols.ExecutorOptions{GlobalMatchers: storage},
		}
		require.False(t, request.needsFullResponse())
	})
}

func TestStoredResponseRebuildsFinding(t *testing.T) {
	event := output.InternalEvent{
		"response":    "",
		"all_headers": "HTTP/1.1 200 OK\r\n\r\n",
		"body":        "hello",
	}
	require.Equal(t, "HTTP/1.1 200 OK\r\n\r\nhello", storedResponse(event))

	event["response"] = "HTTP/1.1 200 OK\r\n\r\nkept"
	require.Equal(t, "HTTP/1.1 200 OK\r\n\r\nkept", storedResponse(event))
}

func TestStatusMatcherSnippetWithoutFullResponse(t *testing.T) {
	request := &Request{}
	matcher := &matchers.Matcher{
		Type:   matchers.MatcherTypeHolder{MatcherType: matchers.StatusMatcher},
		Status: []int{200},
	}
	require.NoError(t, matcher.CompileMatchers())

	event := output.InternalEvent{
		"status_code": 200,
		"body":        "hello",
		"response":    "",
		"all_headers": "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n",
	}
	matched, snippets := request.Match(event, matcher)
	require.True(t, matched)
	require.Equal(t, []string{"HTTP/1.1 200"}, snippets)
}
