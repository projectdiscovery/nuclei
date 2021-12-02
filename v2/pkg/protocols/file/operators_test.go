package file

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

func TestResponseToDSLMap(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-file"
	request := &Request{
		ID:          templateID,
		MaxSize:     1024,
		NoRecursive: false,
		Extensions:  []string{"*", ".lock"},
		DenyList:    []string{".go"},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile file request")

	resp := "test-data\r\n"
	event := request.responseToDSLMap(resp, "one.one.one.one", "one.one.one.one")
	require.Len(t, event, 7, "could not get correct number of items in dsl map")
	require.Equal(t, resp, event["raw"], "could not get correct resp")
}

func TestFileOperatorMatch(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-file"
	request := &Request{
		ID:          templateID,
		MaxSize:     1024,
		NoRecursive: false,
		Extensions:  []string{"*", ".lock"},
		DenyList:    []string{".go"},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile file request")

	resp := "test-data\r\n1.1.1.1\r\n"
	event := request.responseToDSLMap(resp, "one.one.one.one", "one.one.one.one")
	require.Len(t, event, 7, "could not get correct number of items in dsl map")
	require.Equal(t, resp, event["raw"], "could not get correct resp")

	t.Run("valid", func(t *testing.T) {
		matcher := &matchers.Matcher{
			Part:  "raw",
			Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Words: []string{"1.1.1.1"},
		}
		err = matcher.CompileMatchers()
		require.Nil(t, err, "could not compile matcher")

		isMatched, matched := request.Match(event, matcher)
		require.True(t, isMatched, "could not match valid response")
		require.Equal(t, matcher.Words, matched)
	})

	t.Run("negative", func(t *testing.T) {
		matcher := &matchers.Matcher{
			Part:     "raw",
			Type:     matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Negative: true,
			Words:    []string{"random"},
		}
		err := matcher.CompileMatchers()
		require.Nil(t, err, "could not compile negative matcher")

		isMatched, matched := request.Match(event, matcher)
		require.True(t, isMatched, "could not match valid negative response matcher")
		require.Equal(t, []string{}, matched)
	})

	t.Run("invalid", func(t *testing.T) {
		matcher := &matchers.Matcher{
			Part:  "raw",
			Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Words: []string{"random"},
		}
		err := matcher.CompileMatchers()
		require.Nil(t, err, "could not compile matcher")

		isMatched, matched := request.Match(event, matcher)
		require.False(t, isMatched, "could match invalid response matcher")
		require.Equal(t, []string{}, matched)
	})

	t.Run("caseInsensitive", func(t *testing.T) {
		resp := "TEST-DATA\r\n1.1.1.1\r\n"
		event := request.responseToDSLMap(resp, "one.one.one.one", "one.one.one.one")
		require.Len(t, event, 7, "could not get correct number of items in dsl map")
		require.Equal(t, resp, event["raw"], "could not get correct resp")

		matcher := &matchers.Matcher{
			Part:            "raw",
			Type:            matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Words:           []string{"TeSt-DaTA"},
			CaseInsensitive: true,
		}
		err = matcher.CompileMatchers()
		require.Nil(t, err, "could not compile matcher")

		isMatched, matched := request.Match(event, matcher)
		require.True(t, isMatched, "could not match valid response")
		require.Equal(t, []string{"test-data"}, matched)
	})
}

func TestFileOperatorExtract(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-file"
	request := &Request{
		ID:          templateID,
		MaxSize:     1024,
		NoRecursive: false,
		Extensions:  []string{"*", ".lock"},
		DenyList:    []string{".go"},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile file request")

	resp := "test-data\r\n1.1.1.1\r\n"
	event := request.responseToDSLMap(resp, "one.one.one.one", "one.one.one.one")
	require.Len(t, event, 7, "could not get correct number of items in dsl map")
	require.Equal(t, resp, event["raw"], "could not get correct resp")

	t.Run("extract", func(t *testing.T) {
		extractor := &extractors.Extractor{
			Part:  "raw",
			Type:  extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor},
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
			Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.KValExtractor},
			KVal: []string{"raw"},
		}
		err = extractor.CompileExtractors()
		require.Nil(t, err, "could not compile kval extractor")

		data := request.Extract(event, extractor)
		require.Greater(t, len(data), 0, "could not extractor kval valid response")
		require.Equal(t, map[string]struct{}{resp: {}}, data, "could not extract correct kval data")
	})
}

func TestFileMakeResultWithOrMatcher(t *testing.T) {
	expectedValue := []string{"1.1.1.1"}
	namedMatcherName := "test"

	finalEvent := testFileMakeResultOperators(t, "or")
	require.Equal(t, namedMatcherName, finalEvent.Results[0].MatcherName)
	require.Equal(t, expectedValue, finalEvent.OperatorsResult.Matches[namedMatcherName], "could not get matched value")
}

func TestFileMakeResultWithAndMatcher(t *testing.T) {
	finalEvent := testFileMakeResultOperators(t, "and")
	require.Equal(t, "", finalEvent.Results[0].MatcherName)
	require.Empty(t, finalEvent.OperatorsResult.Matches)
}

func testFileMakeResultOperators(t *testing.T, matcherCondition string) *output.InternalWrappedEvent {
	expectedValue := []string{"1.1.1.1"}
	namedMatcherName := "test"
	matcher := []*matchers.Matcher{
		{
			Part:  "raw",
			Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Words: expectedValue,
		},
		{
			Name:  namedMatcherName,
			Part:  "raw",
			Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Words: expectedValue,
		},
	}

	expectedValues := map[string][]string{
		"word-1":         expectedValue,
		namedMatcherName: expectedValue,
	}

	finalEvent := testFileMakeResult(t, matcher, matcherCondition, true)
	for matcherName, matchedValues := range expectedValues {
		var matchesOne = false
		for i := 0; i <= len(expectedValue); i++ {
			resultEvent := finalEvent.Results[i]
			if matcherName == resultEvent.MatcherName {
				matchesOne = true
			}
		}
		require.True(t, matchesOne)
		require.Equal(t, matchedValues, finalEvent.OperatorsResult.Matches[matcherName], "could not get matched value")
	}

	finalEvent = testFileMakeResult(t, matcher, matcherCondition, false)
	require.Equal(t, 1, len(finalEvent.Results))
	return finalEvent
}

func testFileMakeResult(t *testing.T, matchers []*matchers.Matcher, matcherCondition string, isDebug bool) *output.InternalWrappedEvent {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-file"
	request := &Request{
		ID:          templateID,
		MaxSize:     1024,
		NoRecursive: false,
		Extensions:  []string{"*", ".lock"},
		DenyList:    []string{".go"},
		Operators: operators.Operators{
			MatchersCondition: matcherCondition,
			Matchers:          matchers,
			Extractors: []*extractors.Extractor{{
				Part:  "raw",
				Type:  extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor},
				Regex: []string{"[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+"},
			}},
		},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile file request")

	matchedFileName := "test.txt"
	fileContent := "test-data\r\n1.1.1.1\r\n"

	event := request.responseToDSLMap(fileContent, "/tmp", matchedFileName)
	require.Len(t, event, 7, "could not get correct number of items in dsl map")
	require.Equal(t, fileContent, event["raw"], "could not get correct resp")

	finalEvent := &output.InternalWrappedEvent{InternalEvent: event}
	if request.CompiledOperators != nil {
		result, ok := request.CompiledOperators.Execute(event, request.Match, request.Extract, isDebug)
		if ok && result != nil {
			finalEvent.OperatorsResult = result
			finalEvent.Results = request.MakeResultEvent(finalEvent)
		}
	}
	resultEvent := finalEvent.Results[0]
	require.Equal(t, "1.1.1.1", resultEvent.ExtractedResults[0], "could not get correct extracted results")
	require.Equal(t, matchedFileName, resultEvent.Matched, "could not get matched value")

	return finalEvent
}
