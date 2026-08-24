package http

import (
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/stretchr/testify/require"
)

func TestHTTPInputProviderParsesTargetJSONL(t *testing.T) {
	const input = `{"url":"https://one.example","tags":["apache"],"severity":["high"]}
{"url":"https://two.example"}
`

	provider, err := NewHttpInputProvider(&HttpMultiFormatOptions{
		InputMode:     "jsonl",
		InputContents: input,
		Options:       formats.InputFormatOptions{},
	})
	require.NoError(t, err)
	require.EqualValues(t, 2, provider.Count())
	require.Equal(t, "TargetInputProvider", provider.InputType())

	var inputs []*contextargs.MetaInput
	provider.Iterate(func(input *contextargs.MetaInput) bool {
		inputs = append(inputs, input)
		return true
	})
	require.Len(t, inputs, 2)
	require.Equal(t, "https://one.example", inputs[0].Input)
	require.Equal(t, []string{"apache"}, inputs[0].TargetFilter.Tags)
	require.Equal(t, "https://two.example", inputs[1].Input)
	require.NotNil(t, inputs[1].TargetFilter)

	inputs[0].TargetFilter.Tags[0] = "mutated"
	var secondPass []*contextargs.MetaInput
	provider.Iterate(func(input *contextargs.MetaInput) bool {
		secondPass = append(secondPass, input)
		return true
	})
	require.Equal(t, []string{"apache"}, secondPass[0].TargetFilter.Tags)
}

func TestHTTPInputProviderPreservesLegacyJSONL(t *testing.T) {
	provider, err := NewHttpInputProvider(&HttpMultiFormatOptions{
		InputMode: "jsonl",
		InputFile: filepath.Join("..", "..", "formats", "testdata", "ginandjuice.proxify.json"),
		Options:   formats.InputFormatOptions{},
	})
	require.NoError(t, err)
	require.Equal(t, "MultiFormatInputProvider", provider.InputType())
	require.EqualValues(t, 26, provider.Count())

	count := 0
	provider.Iterate(func(input *contextargs.MetaInput) bool {
		require.NotNil(t, input.ReqResp)
		require.Nil(t, input.TargetFilter)
		count++
		return true
	})
	require.Equal(t, 26, count)
}

func TestHTTPInputProviderDoesNotBuildTargetExclusionsForLegacyJSONL(t *testing.T) {
	provider, err := NewHttpInputProvider(&HttpMultiFormatOptions{
		InputMode:      "jsonl",
		InputFile:      filepath.Join("..", "..", "formats", "testdata", "ginandjuice.proxify.json"),
		ExcludeTargets: []string{"["},
		Options:        formats.InputFormatOptions{},
	})

	require.NoError(t, err)
	require.Equal(t, "MultiFormatInputProvider", provider.InputType())
	require.EqualValues(t, 26, provider.Count())
}

func TestHTTPInputProviderValidatesTargetExclusionsForTargetJSONL(t *testing.T) {
	_, err := NewHttpInputProvider(&HttpMultiFormatOptions{
		InputMode:      "jsonl",
		InputContents:  `{"url":"https://example.com"}`,
		ExcludeTargets: []string{"["},
		Options:        formats.InputFormatOptions{},
	})

	require.ErrorContains(t, err, "could not prepare target exclusions")
}

func TestHTTPInputProviderKeepsSameURLWithDifferentFilters(t *testing.T) {
	const input = `{"url":"https://same.example","tags":["apache"]}
{"url":"https://same.example","tags":[]}
`
	inputProvider, err := NewHttpInputProvider(&HttpMultiFormatOptions{
		InputMode:     "jsonl",
		InputContents: input,
		Options:       formats.InputFormatOptions{},
	})
	require.NoError(t, err)
	require.Equal(t, "TargetInputProvider", inputProvider.InputType())

	var ids []string
	inputProvider.Iterate(func(input *contextargs.MetaInput) bool {
		ids = append(ids, input.ID())
		return true
	})
	require.Len(t, ids, 2)
	require.NotEqual(t, ids[0], ids[1])
}

func TestHTTPInputProviderAppliesTargetExclusions(t *testing.T) {
	const input = `{"url":"https://sensitive.example/path","tags":["apache"]}
{"url":"https://192.0.2.25","tags":["apache"]}
{"url":"https://198.51.100.42","tags":["apache"]}
{"url":"https://url-excluded.example/other-path","tags":["apache"]}
{"url":"https://allowed.example/?next=sensitive.example","tags":["apache"]}
{"url":"https://allowed.example","tags":["apache"]}
`
	inputProvider, err := NewHttpInputProvider(&HttpMultiFormatOptions{
		InputMode:     "jsonl",
		InputContents: input,
		ExcludeTargets: []string{
			`^sensitive\.example$`,
			"192.0.2.25",
			"198.51.100.0/24",
			"https://url-excluded.example/specific-path",
		},
		Options: formats.InputFormatOptions{},
	})
	require.NoError(t, err)
	require.Equal(t, "TargetInputProvider", inputProvider.InputType())
	require.EqualValues(t, 2, inputProvider.Count())

	var inputs []*contextargs.MetaInput
	inputProvider.Iterate(func(input *contextargs.MetaInput) bool {
		inputs = append(inputs, input)
		return true
	})
	require.Len(t, inputs, 2)
	require.Equal(t, "https://allowed.example/?next=sensitive.example", inputs[0].Input)
	require.Equal(t, "https://allowed.example", inputs[1].Input)
}

func TestHTTPInputProviderRemainsTargetProviderWhenAllTargetsExcluded(t *testing.T) {
	const input = `{"url":"https://192.0.2.25","tags":["apache"]}`
	inputProvider, err := NewHttpInputProvider(&HttpMultiFormatOptions{
		InputMode:      "jsonl",
		InputContents:  input,
		ExcludeTargets: []string{"192.0.2.0/24"},
		Options:        formats.InputFormatOptions{},
	})

	require.NoError(t, err)
	require.Equal(t, "TargetInputProvider", inputProvider.InputType())
	require.Zero(t, inputProvider.Count())
}
