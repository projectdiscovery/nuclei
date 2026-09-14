package render

import (
	"errors"
	"testing"

	"github.com/projectdiscovery/govaluate"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
	"github.com/stretchr/testify/require"
)

type testURLSource struct {
	urls []string
	data []string
	err  error
}

func (s *testURLSource) NewURLWithData(data string) (string, error) {
	s.data = append(s.data, data)
	if s.err != nil {
		return "", s.err
	}
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

func TestRenderReplacesEncodedTemplateInteractshMarkers(t *testing.T) {
	source := &testURLSource{urls: []string{"https://scan.example/encoded"}}

	result, err := Render(Input{
		Text:       "callback=%7B%7Binteractsh-url%7D%7D",
		Values:     Values{},
		Interactsh: source,
	})

	require.NoError(t, err)
	require.Equal(t, "callback=https://scan.example/encoded", result.Text)
	require.Equal(t, []string{"https://scan.example/encoded"}, result.InteractURLs)
	require.Equal(t, []string{"%7B%7Binteractsh-url%7D%7D"}, source.data)
}

func TestRenderRejectsFailedInteractshAllocation(t *testing.T) {
	source := &testURLSource{err: errors.New("allocation failed")}

	result, err := Render(Input{
		Text:         "callback={{interactsh-url}}",
		Values:       Values{},
		Interactsh:   source,
		InteractURLs: []string{"https://existing.example"},
	})

	require.Error(t, err)
	require.Contains(t, err.Error(), "replace interactsh marker")
	require.Equal(t, "callback={{interactsh-url}}", result.Text)
	require.Equal(t, []string{"https://existing.example"}, result.InteractURLs)
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

func TestRenderDoesNotTreatPipeAsEncodedInteractshBrace(t *testing.T) {
	source := &testURLSource{urls: []string{"https://scan.example/pipe"}}

	result, err := Render(Input{
		Text:       "%7|%7|interactsh-url%7|%7|",
		Values:     Values{},
		Interactsh: source,
	})

	require.NoError(t, err)
	require.Equal(t, "%7|%7|interactsh-url%7|%7|", result.Text)
	require.Empty(t, result.InteractURLs)
	require.Empty(t, source.data)
}

func TestRenderDoesNotTreatMixedRawEncodedBracesAsInteractshMarkers(t *testing.T) {
	items := []struct {
		name string
		text string
	}{
		{name: "mixed opening pair", text: "%7B{interactsh-url}}"},
		{name: "mixed closing pair", text: "{{interactsh-url}%7D"},
		{name: "encoded opening raw closing", text: "%7B%7Binteractsh-url}}"},
		{name: "raw opening encoded closing", text: "{{interactsh-url%7D%7D"},
	}

	for _, item := range items {
		t.Run(item.name, func(t *testing.T) {
			source := &testURLSource{urls: []string{"https://scan.example/mixed"}}

			result, err := Render(Input{
				Text:       item.text,
				Values:     Values{},
				Interactsh: source,
			})

			require.NoError(t, err)
			require.Equal(t, item.text, result.Text)
			require.Empty(t, result.InteractURLs)
			require.Empty(t, source.data)
		})
	}
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

func TestRenderMapPreservesAccumulatedValuesOnError(t *testing.T) {
	calls := 0
	withRenderTestHelperFunction(t, "test_render_map_error", func(args ...interface{}) (interface{}, error) {
		calls++
		if calls == 1 {
			return "rendered", nil
		}
		return nil, errors.New("render failed")
	})

	result, err := RenderMap(MapInput{
		Source: Values{
			"first":  "{{test_render_map_error()}}",
			"second": "{{test_render_map_error()}}",
		},
		Values: Values{},
	})

	require.Error(t, err)
	require.Contains(t, err.Error(), "render failed")
	require.Len(t, result.Values, 1)
	for _, value := range result.Values {
		require.Equal(t, "rendered", value)
	}
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
