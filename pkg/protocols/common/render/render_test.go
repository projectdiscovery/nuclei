package render

import (
	"testing"

	"github.com/projectdiscovery/govaluate"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
	"github.com/stretchr/testify/require"
)

type testURLSource struct {
	urls []string
	data []string
}

func (s *testURLSource) NewURLWithData(data string) (string, error) {
	s.data = append(s.data, data)
	url := "https://scan.example/a b"
	if len(s.urls) > 0 {
		url = s.urls[0]
		s.urls = s.urls[1:]
	}
	return url, nil
}

func withRenderTestHelperFunction(t *testing.T, name string, fn govaluate.ExpressionFunction) {
	t.Helper()

	originalFn, hadFn := dsl.HelperFunctions[name]
	dsl.HelperFunctions[name] = fn
	t.Cleanup(func() {
		if hadFn {
			dsl.HelperFunctions[name] = originalFn
			return
		}
		delete(dsl.HelperFunctions, name)
	})
}

func TestRenderEvaluatesTemplateTextHelpers(t *testing.T) {
	result, err := Render(Input{
		Text:   "{{hex_encode(value)}}",
		Values: Values{"value": "PING"},
	})

	require.NoError(t, err)
	require.Equal(t, "50494e47", result.Text)
	require.Empty(t, result.InteractURLs)
}

func TestRenderTreatsValuesAsData(t *testing.T) {
	var calls int
	withRenderTestHelperFunction(t, "test_side_effect", func(args ...interface{}) (interface{}, error) {
		calls++
		return "executed", nil
	})

	result, err := Render(Input{
		Text: "{{body}}",
		Values: Values{
			"body": "{{test_side_effect(1)}}",
		},
	})

	require.NoError(t, err)
	require.Equal(t, "{{test_side_effect(1)}}", result.Text)
	require.Zero(t, calls)
}

func TestRenderTreatsValuesInsideHelperStringsAsData(t *testing.T) {
	var calls int
	withRenderTestHelperFunction(t, "test_side_effect", func(args ...interface{}) (interface{}, error) {
		calls++
		return true, nil
	})

	result, err := Render(Input{
		Text: "{{contains('{{body}}', 'needle')}}",
		Values: Values{
			"body": "value', 'missing') || test_side_effect() || contains('",
		},
	})

	require.NoError(t, err)
	require.Equal(t, "false", result.Text)
	require.Zero(t, calls)
}

func TestRenderDoesNotEvaluateRenderedOutput(t *testing.T) {
	result, err := Render(Input{
		Text: "{{body}}",
		Values: Values{
			"body":   "{{secret}}",
			"secret": "leaked-secret",
		},
	})

	require.NoError(t, err)
	require.Equal(t, "{{secret}}", result.Text)
}

func TestRenderReplacesTemplateInteractshMarkers(t *testing.T) {
	source := &testURLSource{urls: []string{"https://scan.example/raw"}}

	result, err := Render(Input{
		Text:         "callback={{interactsh-url}}",
		Values:       Values{},
		Interactsh:   source,
		InteractURLs: []string{"https://existing.example"},
	})

	require.NoError(t, err)
	require.Equal(t, "callback=https://scan.example/raw", result.Text)
	require.Equal(t, []string{"https://existing.example", "https://scan.example/raw"}, result.InteractURLs)
	require.Equal(t, []string{"{{interactsh-url}}"}, source.data)
}

func TestRenderTransformsTemplateInteractshMarkersThroughHelpers(t *testing.T) {
	source := &testURLSource{urls: []string{"https://scan.example/a b"}}

	result, err := Render(Input{
		Text:       "{{url_encode('{{interactsh-url}}')}}",
		Values:     Values{},
		Interactsh: source,
	})

	require.NoError(t, err)
	require.Equal(t, "https%3A%2F%2Fscan.example%2Fa%20b", result.Text)
	require.Equal(t, []string{"https://scan.example/a b"}, result.InteractURLs)
	require.Equal(t, []string{"{{interactsh-url}}"}, source.data)
}

func TestRenderDoesNotReplaceInteractshMarkersFromValues(t *testing.T) {
	items := []struct {
		name  string
		value string
	}{
		{name: "raw", value: "{{interactsh-url}}"},
		{name: "encoded", value: "%7B%7Binteractsh-url%7D%7D"},
	}

	for _, item := range items {
		t.Run(item.name, func(t *testing.T) {
			source := &testURLSource{urls: []string{"https://scan.example/value"}}

			result, err := Render(Input{
				Text:       "{{body}}",
				Values:     Values{"body": item.value},
				Interactsh: source,
			})

			require.NoError(t, err)
			require.Equal(t, item.value, result.Text)
			require.Empty(t, result.InteractURLs)
			require.Empty(t, source.data)
		})
	}
}

func TestRenderMapRendersSourceValuesOnce(t *testing.T) {
	source := &testURLSource{urls: []string{"https://scan.example/payload"}}

	result, err := RenderMap(MapInput{
		Source: Values{
			"payload": "{{url_encode('{{interactsh-url}}')}}",
		},
		Values:     Values{},
		Interactsh: source,
	})

	require.NoError(t, err)
	require.Equal(t, "https%3A%2F%2Fscan.example%2Fpayload", result.Values["payload"])
	require.Equal(t, []string{"https://scan.example/payload"}, result.InteractURLs)
	require.Equal(t, []string{"{{interactsh-url}}"}, source.data)
}

func TestRenderMapTreatsValuesAsData(t *testing.T) {
	source := &testURLSource{urls: []string{"https://scan.example/runtime"}}

	result, err := RenderMap(MapInput{
		Source: Values{
			"payload": "{{server_value}}",
		},
		Data: Values{
			"runtime": "kept",
		},
		Values: Values{
			"server_value": "{{interactsh-url}}",
			"runtime":      "kept",
		},
		Interactsh: source,
	})

	require.NoError(t, err)
	require.Equal(t, "{{interactsh-url}}", result.Values["payload"])
	require.Equal(t, "kept", result.Values["runtime"])
	require.Empty(t, result.InteractURLs)
	require.Empty(t, source.data)
}

func TestRenderMapOverlaysDataWithoutRenderingIt(t *testing.T) {
	source := &testURLSource{urls: []string{"https://scan.example/shadowed"}}

	result, err := RenderMap(MapInput{
		Source: Values{
			"payload": "{{interactsh-url}}",
		},
		Data: Values{
			"payload": "runtime-value",
		},
		Values: Values{
			"payload": "runtime-value",
		},
		Interactsh: source,
	})

	require.NoError(t, err)
	require.Equal(t, Values{"payload": "runtime-value"}, result.Values)
	require.Empty(t, result.InteractURLs)
	require.Empty(t, source.data)
}
