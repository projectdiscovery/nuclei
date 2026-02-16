package xsscontext

import (
	"io"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"

	fuzzanalyzers "github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
)

type Analyzer struct{}

var _ fuzzanalyzers.Analyzer = &Analyzer{}

func init() {
	fuzzanalyzers.RegisterAnalyzer("xss_context", &Analyzer{})
}


func (a *Analyzer) Name() string {
	return "xss_context"
}

// ApplyInitialTransformation:
// - If we don't know context yet, we inject a stable marker (probe).
// - If we know context, we replace [XSS] with a context-appropriate payload.
//
// This intentionally allows templates to write payload like: "[XSS]"
// and let analyzer decide the real payload.
func (a *Analyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	marker := ensureMarker(params)

	// If the template uses [XSS], we control the payload.
	if strings.Contains(data, "[XSS]") {
		ctx := getContext(params)
		if ctx == "" {
			// Probe phase: use marker as the payload
			data = strings.ReplaceAll(data, "[XSS]", marker)
		} else {
			data = strings.ReplaceAll(data, "[XSS]", payloadForContext(XSSContext(ctx)))
		}
	}

	// Keep standard [RANDNUM]/[RANDSTR] behavior available.
	data = fuzzanalyzers.ApplyPayloadTransformations(data)
	return data
}

// Analyze:
// Called after a fuzz request completes.
// We do ONE probe request if context isn’t known yet.
// Then we store xss_context in AnalyzerParameters map, which is shared by reference
// with ApplyInitialTransformation, so subsequent payloads become context-aware.
func (a *Analyzer) Analyze(options *fuzzanalyzers.Options) (bool, string, error) {
	if options == nil || options.AnalyzerParameters == nil {
		return false, "", nil
	}

	// Already detected? Do nothing.
	if getContext(options.AnalyzerParameters) != "" {
		return false, "", nil
	}

	gr := options.FuzzGenerated
	if gr.Component == nil {
		return false, "", nil
	}

	// Build probe payload by forcing [XSS] to marker if it exists.
	// If template didn't use [XSS], we still try probing by setting value = marker.
	marker := ensureMarker(options.AnalyzerParameters)

	probePayload := gr.OriginalPayload
	if strings.Contains(probePayload, "[XSS]") {
		probePayload = strings.ReplaceAll(probePayload, "[XSS]", marker)
	}
	probePayload = a.ApplyInitialTransformation(probePayload, options.AnalyzerParameters)

	if err := gr.Component.SetValue(gr.Key, probePayload); err != nil {
		return false, "", errors.Wrap(err, "xss_context: could not set value in component")
	}
	rebuilt, err := gr.Component.Rebuild()
	if err != nil {
		return false, "", errors.Wrap(err, "xss_context: could not rebuild request")
	}

	resp, err := options.HttpClient.Do(rebuilt)
	if err != nil {
		return false, "", errors.Wrap(err, "xss_context: probe request failed")
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", errors.Wrap(err, "xss_context: could not read response body")
	}

	ctx := detectContext(string(bodyBytes), marker)
	options.AnalyzerParameters["xss_context"] = string(ctx)

	// Optional: return "matched" so nuclei output includes analyzer_details (harmless)
	// but we keep it false by default to avoid noisy output.
	gologger.Verbose().Msgf("[xss_context] detected context=%s marker=%s", ctx, marker)
	return false, "xss_context=" + string(ctx), nil
}

func ensureMarker(params map[string]interface{}) string {
	if v, ok := params["xss_marker"]; ok {
		if s, ok2 := v.(string); ok2 && s != "" {
			return s
		}
	}
	// Stable per-run marker: store in params map so probe + detection agree.
	m := "XSSCTX" + strconv.Itoa(fuzzanalyzers.GetRandomInteger())
	params["xss_marker"] = m
	return m
}

func getContext(params map[string]interface{}) string {
	if v, ok := params["xss_context"]; ok {
		if s, ok2 := v.(string); ok2 {
			return s
		}
	}
	return ""
}

func payloadForContext(ctx XSSContext) string {
	switch ctx {
	case ContextHTML:
		return "<script>alert(1)</script>"
	case ContextAttribute:
		return `" onmouseover=alert(1) x="`
	case ContextJS:
		return `";alert(1);//`
	case ContextURL:
		return `javascript:alert(1)`
	default:
		// Safe fallback
		return "<script>alert(1)</script>"
	}
}

