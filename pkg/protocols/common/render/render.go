// Package render centralizes rendering of template text with runtime values.
package render

import (
	"fmt"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/marker"
)

// Values contains render values. Values are inserted as data; they are not
// scanned as new template text after insertion.
type Values = map[string]interface{}

// URLSource allocates URLs for Interactsh markers found in template text.
type URLSource interface {
	NewURLWithData(data string) (string, error)
}

// Input describes a render operation. Text is template text, Values are data,
// and Interactsh is optional source-level marker handling.
type Input struct {
	Text         string
	Values       Values
	Interactsh   URLSource
	InteractURLs []string
}

// Result is the terminal rendered data and any Interactsh URLs allocated while
// rendering template text.
type Result struct {
	Text         string
	InteractURLs []string
}

// MapInput describes a map render operation. Source values are template text.
// Data values are terminal data that override Source and are not rendered.
type MapInput struct {
	Source Values
	Data   Values
	// Values is the evaluation context used while rendering Source.
	Values Values
	// Interactsh and InteractURLs carry source-level Interactsh allocations.
	Interactsh   URLSource
	InteractURLs []string
}

// MapResult contains the complete value map after Source rendering and Data
// overlay, plus any Interactsh URLs allocated while rendering Source values.
type MapResult struct {
	Values       Values
	InteractURLs []string
}

// Render evaluates template text with values and returns rendered data.
//
// Interactsh markers in Text are source-level render effects and are allocated
// before DSL helper evaluation, so helper transforms apply to generated URLs.
// Values are data and rendered output is terminal data; neither is rescanned for
// DSL expressions or Interactsh markers.
func Render(input Input) (Result, error) {
	prepared, err := ReplaceInteractshMarkers(input.Text, input.Interactsh, input.InteractURLs)
	if err != nil {
		return prepared, err
	}

	result, err := expressions.Evaluate(prepared.Text, input.Values)
	if err != nil {
		return prepared, err
	}

	return Result{Text: result, InteractURLs: prepared.InteractURLs}, nil
}

// RenderMap renders Source values as template text, overlays Data values, and
// returns a complete value map. Data keys are skipped while rendering so they
// cannot produce DSL or Interactsh side effects.
//
// It is intended for already-expanded payload iteration maps, not raw payload
// definitions containing lists.
func RenderMap(input MapInput) (MapResult, error) {
	values := make(Values, len(input.Source)+len(input.Data))
	urls := append([]string(nil), input.InteractURLs...)

	for key, value := range input.Source {
		if _, ok := input.Data[key]; ok {
			continue
		}

		result, err := Render(Input{
			Text:         fmt.Sprint(value),
			Values:       input.Values,
			Interactsh:   input.Interactsh,
			InteractURLs: urls,
		})
		if err != nil {
			return MapResult{Values: values, InteractURLs: result.InteractURLs}, err
		}

		values[key] = result.Text
		urls = result.InteractURLs
	}

	for key, value := range input.Data {
		values[key] = value
	}

	return MapResult{Values: values, InteractURLs: urls}, nil
}

// ReplaceInteractshMarkers allocates Interactsh URLs for markers that appear in
// template text. It does not evaluate DSL expressions or inspect values.
func ReplaceInteractshMarkers(text string, source URLSource, interactURLs []string) (Result, error) {
	urls := append([]string(nil), interactURLs...)
	if source == nil {
		return Result{Text: text, InteractURLs: urls}, nil
	}

	for _, interactshURLMarker := range marker.FindInteractshURLMarkers(text) {
		url, err := source.NewURLWithData(interactshURLMarker)
		if err != nil {
			return Result{Text: text, InteractURLs: urls}, fmt.Errorf("replace interactsh marker %q: %w", interactshURLMarker, err)
		}

		urls = append(urls, url)
		text = strings.Replace(text, interactshURLMarker, url, 1)
	}

	return Result{Text: text, InteractURLs: urls}, nil
}
