package globalmatchers

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/stretchr/testify/require"
)

func TestReadsSearchesEveryGlobalMatcher(t *testing.T) {
	var unset *Storage
	require.False(t, unset.Reads("raw_body"))

	storage := New()
	storage.AddOperator(&Item{Operators: []*operators.Operators{{Matchers: []*matchers.Matcher{{Part: "body"}}}}})
	require.False(t, storage.Reads("raw_body", "raw_response"))

	storage.AddOperator(&Item{Operators: []*operators.Operators{{Matchers: []*matchers.Matcher{{Part: "raw_body"}}}}})
	require.True(t, storage.Reads("raw_body", "raw_response"))
}
