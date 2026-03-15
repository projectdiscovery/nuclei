// Package xss implements an XSS context analyzer for the nuclei fuzzer.
//
// It detects reflected payloads in HTTP responses and classifies the HTML
// context of each reflection to determine exploitability. This enables
// context-aware XSS fuzzing with fewer false positives.
package xss

import (
	"fmt"
	"io"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
)

const maxResponseBodySize = 10 * 1024 * 1024 // 10 MB

// Analyzer is an XSS context analyzer for the fuzzer
type Analyzer struct{}

var _ analyzers.Analyzer = &Analyzer{}

func init() {
	analyzers.RegisterAnalyzer("xss_context", &Analyzer{})
}

func (a *Analyzer) Name() string {
	return "xss_context"
}

// ApplyInitialTransformation replaces [XSS_CANARY] with a canary string
// containing HTML/JS-significant probe characters, then applies standard
// payload transformations ([RANDNUM], [RANDSTR]).
func (a *Analyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	prefix := "xss"
	if len(params) > 0 {
		if v, ok := params["canary_prefix"]; ok {
			if s, ok := v.(string); ok && s != "" {
				prefix = s
			}
		}
	}
	canary := buildCanary(prefix)
	data = strings.ReplaceAll(data, "[XSS_CANARY]", canary)
	data = analyzers.ApplyPayloadTransformations(data)
	return data
}

// buildCanary creates a canary string with HTML/JS-significant probe chars.
func buildCanary(prefix string) string {
	randStr := fmt.Sprintf("%d", analyzers.GetRandomInteger())
	return prefix + randStr + "<>'\"`"
}

// Analyze checks for reflected XSS by looking for the canary in the response
// body and classifying the injection context.
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	gr := options.FuzzGenerated
	payload := a.ApplyInitialTransformation(gr.OriginalPayload, options.AnalyzerParameters)
	if payload == "" {
		return false, "", nil
	}

	body := options.ResponseBody
	// If response body not provided in options, re-issue the request
	if body == "" {
		if err := gr.Component.SetValue(gr.Key, payload); err != nil {
			return false, "", errors.Wrap(err, "could not set value in component")
		}
		defer func() {
			// Restore original value
			_ = gr.Component.SetValue(gr.Key, gr.Value)
		}()

		rebuilt, err := gr.Component.Rebuild()
		if err != nil {
			return false, "", errors.Wrap(err, "could not rebuild request")
		}
		gologger.Verbose().Msgf("[%s] Sending request for: %s", a.Name(), rebuilt.String())

		resp, err := options.HttpClient.Do(rebuilt)
		if err != nil {
			return false, "", errors.Wrap(err, "could not do request")
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
		if err != nil {
			return false, "", errors.Wrap(err, "could not read response body")
		}
		body = string(bodyBytes)
	}

	findings := classifyReflections(body, payload)
	if len(findings) == 0 {
		return false, "", nil
	}

	return true, formatFindings(findings), nil
}
