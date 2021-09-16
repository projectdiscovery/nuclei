package network

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v2/internal/testutils"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
)

func TestResponseToDSLMap(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-network"
	request := &Request{
		ID:       templateID,
		Address:  []string{"{{Hostname}}"},
		ReadSize: 1024,
		Inputs:   []*Input{{Data: "test-data\r\n"}},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile network request")

	req := "test-data\r\n"
	resp := "resp-data\r\n"
	event := request.responseToDSLMap(req, resp, "test", "one.one.one.one", "one.one.one.one")
	require.Len(t, event, 8, "could not get correct number of items in dsl map")
	require.Equal(t, resp, event["data"], "could not get correct resp")
}

func TestNetworkOperatorMatch(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-network"
	request := &Request{
		ID:       templateID,
		Address:  []string{"{{Hostname}}"},
		ReadSize: 1024,
		Inputs:   []*Input{{Data: "test-data\r\n"}},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile network request")

	req := "test-data\r\n"
	resp := "resp-data\r\nSTAT \r\n"
	event := request.responseToDSLMap(req, resp, "one.one.one.one", "one.one.one.one", "test")

	t.Run("valid", func(t *testing.T) {
		matcher := &matchers.Matcher{
			Part:  "body",
			Type:  "word",
			Words: []string{"STAT "},
		}
		err = matcher.CompileMatchers()
		require.Nil(t, err, "could not compile matcher")

		matched := request.Match(event, matcher)
		require.True(t, matched, "could not match valid response")
	})

	t.Run("negative", func(t *testing.T) {
		matcher := &matchers.Matcher{
			Part:     "data",
			Type:     "word",
			Negative: true,
			Words:    []string{"random"},
		}
		err := matcher.CompileMatchers()
		require.Nil(t, err, "could not compile negative matcher")

		matched := request.Match(event, matcher)
		require.True(t, matched, "could not match valid negative response matcher")
	})

	t.Run("invalid", func(t *testing.T) {
		matcher := &matchers.Matcher{
			Part:  "data",
			Type:  "word",
			Words: []string{"random"},
		}
		err := matcher.CompileMatchers()
		require.Nil(t, err, "could not compile matcher")

		matched := request.Match(event, matcher)
		require.False(t, matched, "could match invalid response matcher")
	})
}

func TestNetworkOperatorExtract(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-network"
	request := &Request{
		ID:       templateID,
		Address:  []string{"{{Hostname}}"},
		ReadSize: 1024,
		Inputs:   []*Input{{Data: "test-data\r\n"}},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile network request")

	req := "test-data\r\n"
	resp := "resp-data\r\nSTAT \r\n1.1.1.1\r\n"
	event := request.responseToDSLMap(req, resp, "one.one.one.one", "one.one.one.one", "test")

	t.Run("extract", func(t *testing.T) {
		extractor := &extractors.Extractor{
			Part:  "data",
			Type:  "regex",
			Regex: []string{"[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+"},
		}
		err = extractor.CompileExtractors()
		require.Nil(t, err, "could not compile extractor")

		data := request.Extract(event, extractor)
		require.Greater(t, len(data), 0, "could not extractor valid response")
		require.Equal(t, map[string]struct{}{"1.1.1.1": {}}, data, "could not extract correct data")
	})

	t.Run("kval", func(t *testing.T) {
		extractor := &extractors.Extractor{
			Type: "kval",
			KVal: []string{"request"},
		}
		err = extractor.CompileExtractors()
		require.Nil(t, err, "could not compile kval extractor")

		data := request.Extract(event, extractor)
		require.Greater(t, len(data), 0, "could not extractor kval valid response")
		require.Equal(t, map[string]struct{}{req: {}}, data, "could not extract correct kval data")
	})
}

func TestNetworkMakeResult(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-network"
	request := &Request{
		ID:       templateID,
		Address:  []string{"{{Hostname}}"},
		ReadSize: 1024,
		Inputs:   []*Input{{Data: "test-data\r\n"}},
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Name:  "test",
				Part:  "data",
				Type:  "word",
				Words: []string{"STAT "},
			}},
			Extractors: []*extractors.Extractor{{
				Part:  "data",
				Type:  "regex",
				Regex: []string{"[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+"},
			}},
		},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile network request")

	req := "test-data\r\n"
	resp := "resp-data\rSTAT \r\n1.1.1.1\n"
	event := request.responseToDSLMap(req, resp, "one.one.one.one", "one.one.one.one", "test")
	finalEvent := &output.InternalWrappedEvent{InternalEvent: event}
	event["ip"] = "192.168.1.1"
	if request.CompiledOperators != nil {
		result, ok := request.CompiledOperators.Execute(event, request.Match, request.Extract)
		if ok && result != nil {
			finalEvent.OperatorsResult = result
			finalEvent.Results = request.MakeResultEvent(finalEvent)
		}
	}
	require.Equal(t, 1, len(finalEvent.Results), "could not get correct number of results")
	require.Equal(t, "test", finalEvent.Results[0].MatcherName, "could not get correct matcher name of results")
	require.Equal(t, "1.1.1.1", finalEvent.Results[0].ExtractedResults[0], "could not get correct extracted results")
}
