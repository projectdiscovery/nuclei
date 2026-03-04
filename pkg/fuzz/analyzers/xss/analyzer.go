package xss

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
)

// Analyzer is an XSS context analyzer for the fuzzer.
// It detects the reflection context of injected payloads and
// verifies XSS by replaying context-appropriate payloads.
type Analyzer struct{}

var _ analyzers.Analyzer = &Analyzer{}

func init() {
	analyzers.RegisterAnalyzer("xss_context", &Analyzer{})
}

// Name returns the name of the analyzer
func (a *Analyzer) Name() string {
	return "xss_context"
}

// ApplyInitialTransformation replaces placeholder tokens in the payload.
//
// It supports:
//   - [XSS_CANARY] => unique canary string with XSS-critical characters for reflection/context detection
//
// It also applies the standard [RANDNUM] and [RANDSTR] transformations.
func (a *Analyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	if strings.Contains(data, "[XSS_CANARY]") {
		canary := generateCanary()
		if params != nil {
			params["xss_canary"] = canary
		}
		// The canary includes special chars for character survival detection
		canaryWithChars := canary + canaryChars
		data = strings.ReplaceAll(data, "[XSS_CANARY]", canaryWithChars)
	}
	data = analyzers.ApplyPayloadTransformations(data)
	return data
}

// generateCanary creates a unique canary string
func generateCanary() string {
	return "nuclei" + analyzers.RandStringBytesMask(8)
}

// Analyze detects XSS vulnerabilities by:
// 1. Checking for canary reflection in the initial response
// 2. Detecting the HTML context of the reflection
// 3. Replaying context-appropriate payloads to verify exploitability
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	// Determine the canary from parameters
	canary := ""
	if v, ok := options.AnalyzerParameters["xss_canary"]; ok {
		canary, _ = v.(string)
	}
	if canary == "" {
		// Attempt to extract from FuzzGenerated value if missing from parameters
		if options.FuzzGenerated.Value != "" {
			const prefix = "nuclei"
			val := options.FuzzGenerated.Value
			lower := strings.ToLower(val)
			if idx := strings.Index(lower, prefix); idx >= 0 && idx+len(prefix)+8 <= len(val) {
				canary = val[idx : idx+len(prefix)+8]
			}
		}
		if canary == "" {
			return false, "", nil
		}
	}

	body := options.ResponseBody
	if body == "" {
		return false, "", nil
	}

	// Check Content-Type - only analyze HTML responses
	if !isHTMLResponse(options.ResponseHeaders) {
		return false, "", nil
	}

	// Check if canary is reflected at all (case-insensitive)
	if !strings.Contains(strings.ToLower(body), strings.ToLower(canary)) {
		return false, "", nil
	}

	// Detect character survival
	chars := detectCharacterSurvival(body, canary)

	// Detect reflection contexts using the HTML tokenizer
	reflections := DetectReflections(body, canary)
	if len(reflections) == 0 {
		return false, "", nil
	}

	best := BestReflection(reflections)
	if best == nil || best.Context == ContextNone {
		return false, "", nil
	}

	// Select payloads appropriate for the detected context
	payloads := selectPayloads(best, chars)
	if len(payloads) == 0 {
		return false, "", fmt.Errorf("no suitable payloads for context %s", best.Context)
	}

	// Replay with context-appropriate payloads
	for _, payload := range payloads {
		matched, details, err := a.replayAndVerify(options, payload, best)
		if err != nil {
			gologger.Verbose().Msgf("[%s] replay error: %v", a.Name(), err)
			continue
		}
		if matched {
			return true, details, nil
		}
	}

	return false, "", nil
}

// replayAndVerify sends a request with the given payload and checks
// if the payload appears unencoded in the response.
func (a *Analyzer) replayAndVerify(options *analyzers.Options, payload string, reflection *ReflectionInfo) (bool, string, error) {
	gr := options.FuzzGenerated

	if gr.Component == nil {
		return false, "", errors.New("fuzz component is nil")
	}

	origPayload := gr.OriginalPayload

	// Set the payload into the component
	if err := gr.Component.SetValue(gr.Key, payload); err != nil {
		return false, "", errors.Wrap(err, "could not set value in component")
	}
	// Restore original value after rebuild so subsequent replays start from clean state
	// Register defer immediately after SetValue to ensure restoration even if Rebuild fails
	defer func() {
		_ = gr.Component.SetValue(gr.Key, gr.OriginalValue)
	}()

	rebuilt, err := gr.Component.Rebuild()
	if err != nil {
		return false, "", errors.Wrap(err, "could not rebuild request")
	}

	gologger.Verbose().Msgf("[%s] Replaying with payload for %s context: %s", a.Name(), reflection.Context, rebuilt.String())

	resp, err := options.HttpClient.Do(rebuilt)
	if err != nil {
		return false, "", errors.Wrap(err, "could not send replay request")
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", errors.Wrap(err, "could not read replay response body")
	}

	respBodyStr := string(respBody)

	// Check if the payload is reflected unencoded
	if strings.Contains(respBodyStr, payload) {
		details := fmt.Sprintf(
			"[xss_context] XSS confirmed in %s context (tag: %s, param: %s). Payload reflected unencoded: %s (original: %s)",
			reflection.Context,
			reflection.TagName,
			gr.Key,
			payload,
			origPayload,
		)

		if hasCSP(resp.Header) {
			details += " [note: CSP header present, may limit exploitability]"
		}

		return true, details, nil
	}

	return false, "", nil
}

// isHTMLResponse checks if the Content-Type indicates an HTML response
func isHTMLResponse(headers map[string][]string) bool {
	if headers == nil {
		return true // assume HTML if no headers available
	}
	ct := getHeader(headers, "Content-Type")
	if ct == "" {
		return true // assume HTML if no Content-Type
	}
	ctLower := strings.ToLower(ct)
	return strings.Contains(ctLower, "text/html") || strings.Contains(ctLower, "application/xhtml")
}

// hasCSP checks if Content-Security-Policy header is present
func hasCSP(headers map[string][]string) bool {
	if headers == nil {
		return false
	}
	return getHeader(headers, "Content-Security-Policy") != ""
}

// getHeader gets the first value for a header (case-insensitive)
func getHeader(headers map[string][]string, name string) string {
	// http.Header is already canonical, use direct lookup first
	if vals, ok := headers[http.CanonicalHeaderKey(name)]; ok && len(vals) > 0 {
		return vals[0]
	}
	// Fallback: case-insensitive search
	nameLower := strings.ToLower(name)
	for k, vals := range headers {
		if strings.ToLower(k) == nameLower && len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}

// detectCharacterSurvival checks which XSS-critical characters survived server-side encoding
func detectCharacterSurvival(body string, canary string) CharacterSet {
	var cs CharacterSet

	// Find all occurrences of canary (case-insensitive)
	lowerBody := strings.ToLower(body)
	lowerCanary := strings.ToLower(canary)

	start := 0
	for {
		idx := strings.Index(lowerBody[start:], lowerCanary)
		if idx == -1 {
			break
		}
		currIdx := start + idx
		// Check a window after the canary for the survival of special characters
		endIdx := currIdx + len(canary) + 30
		if endIdx > len(body) {
			endIdx = len(body)
		}

		window := body[currIdx+len(canary) : endIdx]

		if !cs.LessThan && strings.Contains(window, "<") {
			cs.LessThan = true
		}
		if !cs.GreaterThan && strings.Contains(window, ">") {
			cs.GreaterThan = true
		}
		if !cs.DoubleQuote && strings.Contains(window, `"`) {
			cs.DoubleQuote = true
		}
		if !cs.SingleQuote && strings.Contains(window, "'") {
			cs.SingleQuote = true
		}
		if !cs.ForwardSlash && strings.Contains(window, "/") {
			cs.ForwardSlash = true
		}

		if cs.LessThan && cs.GreaterThan && cs.DoubleQuote && cs.SingleQuote && cs.ForwardSlash {
			break
		}

		start = currIdx + 1
	}

	return cs
}

// selectPayloads returns context-appropriate XSS payloads filtered by character availability
func selectPayloads(reflection *ReflectionInfo, chars CharacterSet) []string {
	var candidates []string

	switch reflection.Context {
	case ContextHTMLText:
		if chars.LessThan && chars.GreaterThan {
			candidates = []string{
				`<img src=x onerror=alert(1)>`,
				`<svg onload=alert(1)>`,
				`<details open ontoggle=alert(1)>`,
			}
		}

	case ContextAttribute:
		if reflection.QuoteChar == '"' && chars.DoubleQuote {
			candidates = []string{
				`" onfocus=alert(1) autofocus="`,
				`" onmouseover=alert(1) "`,
				`"><img src=x onerror=alert(1)>`,
			}
		} else if reflection.QuoteChar == '\'' && chars.SingleQuote {
			candidates = []string{
				`' onfocus=alert(1) autofocus='`,
				`' onmouseover=alert(1) '`,
				`'><img src=x onerror=alert(1)>`,
			}
		}
		// If angle brackets available, try tag breakout even without matching quotes
		if len(candidates) == 0 && chars.LessThan && chars.GreaterThan {
			candidates = []string{
				`"><img src=x onerror=alert(1)>`,
				`'><img src=x onerror=alert(1)>`,
			}
		}

	case ContextAttributeUnquoted:
		candidates = []string{
			` onfocus=alert(1) autofocus`,
			` onmouseover=alert(1)`,
		}
		if chars.LessThan && chars.GreaterThan {
			candidates = append(candidates, `><img src=x onerror=alert(1)>`)
		}

	case ContextScript:
		candidates = []string{
			`</script><img src=x onerror=alert(1)>`,
			`;alert(1)//`,
			`\nalert(1)//`,
		}

	case ContextScriptString:
		if chars.SingleQuote {
			candidates = append(candidates, `';alert(1)//`)
		}
		if chars.DoubleQuote {
			candidates = append(candidates, `";alert(1)//`)
		}
		if chars.LessThan && chars.GreaterThan {
			candidates = append(candidates, `</script><img src=x onerror=alert(1)>`)
		}
		if len(candidates) == 0 {
			candidates = []string{`</script><img src=x onerror=alert(1)>`}
		}

	case ContextStyle:
		candidates = []string{
			`</style><img src=x onerror=alert(1)>`,
		}

	case ContextHTMLComment:
		candidates = []string{
			`--><img src=x onerror=alert(1)>`,
		}
	}

	return candidates
}
