package http

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/stretchr/testify/require"
)

func TestCanShareResponseKeepsTimingChecksOnTheirOwnRequest(t *testing.T) {
	require.True(t, canShareResponse(&Request{Operators: operators.Operators{Matchers: []*matchers.Matcher{{Words: []string{"admin"}}}}}, ""))
	require.False(t, canShareResponse(&Request{Operators: operators.Operators{Matchers: []*matchers.Matcher{{DSL: []string{"duration>=5"}}}}}, ""))
	require.False(t, canShareResponse(&Request{Operators: operators.Operators{Matchers: []*matchers.Matcher{{Part: "duration"}}}}, ""))
	require.False(t, canShareResponse(&Request{Operators: operators.Operators{Extractors: []*extractors.Extractor{{DSL: []string{"duration_2"}}}}}, ""))
	require.False(t, canShareResponse(&Request{Operators: operators.Operators{Matchers: []*matchers.Matcher{{Type: matchers.MatcherTypeHolder{MatcherType: matchers.LLMMatcher}, Inputs: []string{"{{duration_1}}"}}}}}, ""), "llm inputs read the event too")
	require.False(t, canShareResponse(&Request{}, "http(1) && template.duration > 5"))
	require.False(t, canShareResponse(&Request{Race: true}, ""))
}
