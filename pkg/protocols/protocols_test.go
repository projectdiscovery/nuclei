package protocols

import (
	"reflect"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/stretchr/testify/require"
)

func TestCloneOperatorsCopiesAuthoredFields(t *testing.T) {
	source := operators.Operators{
		MatchersCondition: "and",
		TemplateID:        "cached-template",
		Matchers: []*matchers.Matcher{
			{
				Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
				Words: []string{"first"},
			},
		},
		Extractors: []*extractors.Extractor{
			{
				Type:  extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor},
				Regex: []string{"token=(.+)"},
			},
		},
	}

	cloned := CloneOperators(source)

	require.Equal(t, source.MatchersCondition, cloned.MatchersCondition)
	require.Empty(t, cloned.TemplateID)
	require.Nil(t, cloned.ExcludeMatchers)
	require.Equal(t, source.Matchers[0].Words, cloned.Matchers[0].Words)
	require.Equal(t, source.Extractors[0].Regex, cloned.Extractors[0].Regex)
	require.NotSame(t, source.Matchers[0], cloned.Matchers[0])
	require.NotSame(t, source.Extractors[0], cloned.Extractors[0])

	cloned.Matchers[0].Words[0] = "second"
	cloned.Extractors[0].Regex[0] = "session=(.+)"
	require.Equal(t, "first", source.Matchers[0].Words[0])
	require.Equal(t, "token=(.+)", source.Extractors[0].Regex[0])
}

func TestCloneOperatorsHandlesZeroValue(t *testing.T) {
	cloned := CloneOperators(operators.Operators{})
	require.Empty(t, cloned.Matchers)
	require.Empty(t, cloned.Extractors)
}

func TestCloneMatchersCopiesDefinitions(t *testing.T) {
	source := []*matchers.Matcher{
		{
			Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Words: []string{"first"},
		},
	}

	cloned := CloneMatchers(source)

	require.Equal(t, source[0].Words, cloned[0].Words)
	require.NotSame(t, source[0], cloned[0])

	cloned[0].Words[0] = "second"
	require.Equal(t, "first", source[0].Words[0])
	require.Nil(t, CloneMatchers(nil))
}

func TestCloneExportedValueCopiesCompositeFields(t *testing.T) {
	type cloneFixture struct {
		Any      any
		Ptr      *int
		NilPtr   *int
		Slice    []string
		NilSlice []string
		Map      map[string][]int
		NilMap   map[string]string
		Array    [2]*int
	}

	first := 1
	second := 2
	source := cloneFixture{
		Any:   []string{"value"},
		Ptr:   &first,
		Slice: []string{"a", "b"},
		Map:   map[string][]int{"numbers": {1, 2}},
		Array: [2]*int{&first, &second},
	}

	cloned := cloneExportedValue(reflect.ValueOf(source)).Interface().(cloneFixture)

	require.Equal(t, source.Any, cloned.Any)
	require.Equal(t, source.Slice, cloned.Slice)
	require.Equal(t, source.Map, cloned.Map)
	require.NotSame(t, source.Ptr, cloned.Ptr)
	require.NotSame(t, source.Array[0], cloned.Array[0])
	require.Nil(t, cloned.NilPtr)
	require.Nil(t, cloned.NilSlice)
	require.Nil(t, cloned.NilMap)

	cloned.Any.([]string)[0] = "changed"
	cloned.Slice[0] = "changed"
	cloned.Map["numbers"][0] = 3
	*cloned.Ptr = 4
	*cloned.Array[0] = 5

	require.Equal(t, []string{"value"}, source.Any)
	require.Equal(t, []string{"a", "b"}, source.Slice)
	require.Equal(t, []int{1, 2}, source.Map["numbers"])
	require.Equal(t, 1, *source.Ptr)
	require.Equal(t, 1, *source.Array[0])
}

func TestCloneExportedValueHandlesInvalidValue(t *testing.T) {
	require.False(t, cloneExportedValue(reflect.Value{}).IsValid())
}
