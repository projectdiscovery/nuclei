package xss

import (
	"io"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
)

// classifyContexts detects whether payload is reflected and tries to infer a rough context.
// This is intentionally lightweight (no HTML parser) and is meant for fuzzing guidance.
func classifyContexts(body, payload string) (bool, string) {
	if payload == "" {
		return false, ""
	}
	idx := strings.Index(body, payload)
	if idx < 0 {
		return false, ""
	}

	before := body[:idx]
	// comment context
	if strings.LastIndex(before, "<!--") > strings.LastIndex(before, "-->") {
		return true, "reflected payload detected in html_comment context"
	}
	// script context
	lowerBefore := strings.ToLower(before)
	if strings.LastIndex(lowerBefore, "<script") > strings.LastIndex(lowerBefore, "</script>") {
		return true, "reflected payload detected in script context"
	}
	// tag/attribute context
	lastLt := strings.LastIndex(before, "<")
	lastGt := strings.LastIndex(before, ">")
	if lastLt > lastGt {
		// inside a tag declaration; assume attribute-ish
		return true, "reflected payload detected in html_attribute context"
	}

	return true, "reflected payload detected in html context"
}

const (
	analyzerName        = "xss_context"
	maxResponseBodySize = 10 << 20 // 10MB
)

// Analyzer is a first-pass XSS analyzer that validates reflection.
// Context classification is implemented in follow-up steps.
type Analyzer struct{}

var _ analyzers.Analyzer = &Analyzer{}

func init() {
	analyzers.RegisterAnalyzer(analyzerName, &Analyzer{})
}

// Name returns the registered analyzer name.
func (a *Analyzer) Name() string {
	return analyzerName
}

// ApplyInitialTransformation applies standard fuzz payload transformations (e.g. [RANDNUM]) to the analyzer input.
func (a *Analyzer) ApplyInitialTransformation(data string, _ map[string]interface{}) string {
	return analyzers.ApplyPayloadTransformations(data)
}

// Analyze replays a fuzz-generated request with the transformed payload injected and reports reflection + rough HTML context.
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	if options == nil || options.FuzzGenerated.Component == nil || options.HttpClient == nil {
		return false, "", nil
	}

	gr := options.FuzzGenerated
	payload := a.ApplyInitialTransformation(gr.Value, options.AnalyzerParameters)
	if payload == "" {
		return false, "", nil
	}

	if err := gr.Component.SetValue(gr.Key, payload); err != nil {
		return false, "", err
	}
	defer func() {
		_ = gr.Component.SetValue(gr.Key, gr.Value)
	}()

	rebuilt, err := gr.Component.Rebuild()
	if err != nil {
		return false, "", err
	}

	resp, err := options.HttpClient.Do(rebuilt)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return false, "", err
	}

	matched, reason := classifyContexts(string(body), payload)
	if matched {
		return true, reason, nil
	}

	return false, "", nil
}
