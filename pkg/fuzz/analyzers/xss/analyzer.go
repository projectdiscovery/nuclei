package xss

import (
	"fmt"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
)

// Analyzer detects the HTML rendering context of reflected values.
type Analyzer struct{}

var _ analyzers.Analyzer = &Analyzer{}

func init() {
	analyzers.RegisterAnalyzer("xss_context", &Analyzer{})
}

// Name returns the analyzer identifier.
func (a *Analyzer) Name() string {
	return "xss_context"
}

// ApplyInitialTransformation replaces [XSS_MARKER] with a unique canary and persists it in params.
func (a *Analyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	data = analyzers.ApplyPayloadTransformations(data)
	if strings.Contains(data, "[XSS_MARKER]") {
		marker := "nuclei" + analyzers.RandStringBytesMask(8)
		data = strings.ReplaceAll(data, "[XSS_MARKER]", marker)
		if params != nil {
			params["xss_marker"] = marker
		}
	}
	return data
}

// Analyze classifies the HTML context of a reflected canary in the response body
// and verifies exploitability by analyzing Content-Type, CSP, and quoting.
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	if options.ResponseBody == "" {
		return false, "", nil
	}
	reflectedValue := ""
	if options.AnalyzerParameters != nil {
		if marker, ok := options.AnalyzerParameters["xss_marker"].(string); ok {
			reflectedValue = marker
		}
	}
	if reflectedValue == "" {
		reflectedValue = options.FuzzGenerated.Value
	}
	if reflectedValue == "" {
		return false, "", nil
	}
	ctx := DetectContext(options.ResponseBody, reflectedValue)
	if ctx == ContextNone {
		return false, "", nil
	}
	exploitable, detail := VerifyContext(
		options.ResponseBody,
		options.ResponseHeaders,
		reflectedValue,
		ctx,
	)
	if !exploitable {
		return false, "", nil
	}
	result := fmt.Sprintf(
		"[xss_context] %s reflection for parameter '%s' (%s)",
		ctx.String(),
		options.FuzzGenerated.Parameter,
		detail,
	)
	return true, result, nil
}
