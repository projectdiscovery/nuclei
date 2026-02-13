package xss

import (
	"fmt"
	"io"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Analyzer implements the XSS context analyzer for the nuclei fuzzing engine.
// It works by:
// 1. Injecting a canary string containing XSS-critical characters into the payload
// 2. Checking the response for reflections of the canary
// 3. Classifying the HTML context of each reflection
// 4. Determining whether the reflection is exploitable based on which
//    characters survive encoding/sanitization in that context
type Analyzer struct{}

var _ analyzers.Analyzer = &Analyzer{}

const (
	// canaryPrefix is the static prefix used to identify our probe in responses.
	canaryPrefix = "xc4n4ry"
	// probeChars are XSS-critical characters included in the canary to test
	// which ones survive sanitization. Order matters: </ must be adjacent for
	// style/script breakout detection; - and > for comment breakout.
	probeChars = `</>'"` + "`-"
)

func init() {
	analyzers.RegisterAnalyzer("xss_context", &Analyzer{})
}

// Name returns the name of this analyzer.
func (a *Analyzer) Name() string {
	return "xss_context"
}

// ApplyInitialTransformation replaces placeholder tokens in the payload with
// a unique canary string that includes XSS-critical characters.
//
// Supported placeholders:
//   - [XSS_CANARY] => the full canary with probe chars
//   - [RANDNUM] / [RANDSTR] => random values (handled by base transformer)
func (a *Analyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	canary := buildCanary(params)
	data = strings.ReplaceAll(data, "[XSS_CANARY]", canary)
	data = analyzers.ApplyPayloadTransformations(data)
	return data
}

// Analyze examines the HTTP response for reflections of the canary and
// determines if any reflection point is exploitable for XSS.
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	canary := buildCanary(options.AnalyzerParameters)

	// If a response body is directly available, use it
	if options.ResponseBody != "" {
		return a.analyzeBody(options.ResponseBody, canary, options.AnalyzerParameters)
	}

	// Otherwise, send a probe request to get the response
	gr := options.FuzzGenerated
	if gr.Component == nil {
		return false, "", nil
	}

	// Set the canary value in the component
	probeValue := canary
	if err := gr.Component.SetValue(gr.Key, probeValue); err != nil {
		return false, "", errors.Wrap(err, "could not set canary value")
	}

	rebuilt, err := gr.Component.Rebuild()
	if err != nil {
		return false, "", errors.Wrap(err, "could not rebuild request")
	}

	gologger.Verbose().Msgf("[%s] Sending XSS canary probe: %s", a.Name(), rebuilt.String())

	body, err := doRequest(rebuilt, options.HttpClient)
	if err != nil {
		return false, "", errors.Wrap(err, "could not send canary probe")
	}

	return a.analyzeBody(body, canary, options.AnalyzerParameters)
}

// analyzeBody checks the response body for reflected canary strings and
// classifies their contexts.
func (a *Analyzer) analyzeBody(body, canary string, params map[string]interface{}) (bool, string, error) {
	reflections := ClassifyReflections(body, canary)
	if len(reflections) == 0 {
		return false, "", nil
	}

	// Check each reflection for exploitability
	var exploitable []Reflection
	for _, ref := range reflections {
		if isExploitable(body, canary, ref) {
			exploitable = append(exploitable, ref)
		}
	}

	if len(exploitable) == 0 {
		return false, "", nil
	}

	// Build a details string describing the findings
	details := formatFindings(exploitable)
	return true, details, nil
}

// isExploitable checks whether a reflection point has enough unescaped
// characters to be exploitable in its context.
func isExploitable(body, canary string, ref Reflection) bool {
	// Extract the actual reflected content from the response
	if ref.Position+len(canary) > len(body) {
		return false
	}
	reflected := body[ref.Position : ref.Position+len(canary)]

	switch ref.Context {
	case ContextHTMLBody:
		// Need < and > to inject tags
		return strings.Contains(reflected, "<") && strings.Contains(reflected, ">")

	case ContextHTMLAttrDoubleQuoted:
		// Need " to break out of attribute
		return strings.Contains(reflected, "\"")

	case ContextHTMLAttrSingleQuoted:
		// Need ' to break out of attribute
		return strings.Contains(reflected, "'")

	case ContextHTMLAttrUnquoted:
		// Need space or > to break out
		return strings.Contains(reflected, " ") || strings.Contains(reflected, ">")

	case ContextScriptStringDouble:
		// Need unescaped " or ability to use </script>
		return strings.Contains(reflected, "\"") || strings.Contains(reflected, "</")

	case ContextScriptStringSingle:
		// Need unescaped ' or ability to use </script>
		return strings.Contains(reflected, "'") || strings.Contains(reflected, "</")

	case ContextScriptTemplate:
		// Need ` or ${ to break out
		return strings.Contains(reflected, "`") || strings.Contains(reflected, "${")

	case ContextScriptBlock:
		// Already in executable context — just need </ to break out,
		// or the content itself may be directly executable
		return true

	case ContextHTMLComment:
		// Need --> to break out of the comment. The second disjunct is a
		// heuristic: if both '-' and '>' survive encoding (even non-adjacently),
		// an attacker can likely craft a payload containing "-->". This errs on
		// the side of over-reporting, which is acceptable for a probe-based
		// design where a follow-up confirmation payload is used.
		return strings.Contains(reflected, "-->") || (strings.Contains(reflected, "-") && strings.Contains(reflected, ">"))

	case ContextStyleBlock:
		// Need </ to break out
		return strings.Contains(reflected, "</")

	case ContextURLAttribute:
		// Check for javascript: protocol. Use asciiToLower for consistency
		// with the rest of the package (avoids byte-offset issues on non-ASCII).
		lowerReflected := asciiToLower(reflected)
		return strings.Contains(lowerReflected, "javascript:") || strings.Contains(reflected, "\"") || strings.Contains(reflected, "'")

	default:
		return false
	}
}

// formatFindings creates a human-readable description of exploitable reflections.
func formatFindings(reflections []Reflection) string {
	var parts []string
	for _, ref := range reflections {
		parts = append(parts, fmt.Sprintf("context=%s position=%d", ref.Context.String(), ref.Position))
	}
	return fmt.Sprintf("XSS reflected in %d context(s): %s", len(reflections), strings.Join(parts, "; "))
}

// buildCanary constructs the canary string, optionally using a custom prefix
// from parameters.
func buildCanary(params map[string]interface{}) string {
	prefix := canaryPrefix
	if params != nil {
		if v, ok := params["canary_prefix"]; ok {
			if s, ok := v.(string); ok && s != "" {
				prefix = s
			}
		}
	}
	// Include all probe chars so we can test which ones survive
	return prefix + probeChars + prefix
}

// doRequest sends an HTTP request and returns the response body as a string.
func doRequest(req *retryablehttp.Request, client *retryablehttp.Client) (string, error) {
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Limit read to 10 MB to match the main request path and prevent OOM.
	const maxProbeRead = 10 * 1024 * 1024
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxProbeRead))
	if err != nil {
		return "", err
	}
	return string(bodyBytes), nil
}
