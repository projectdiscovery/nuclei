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
//
// The generated canary is embedded directly into the transformed payload
// (prefixed with "nuclei") rather than stored in the shared params map,
// avoiding race conditions with concurrent fuzzing.
func (a *Analyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	if strings.Contains(data, "[XSS_CANARY]") {
		canary := generateCanary()
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

// canaryPrefix is the static prefix used to locate the canary in fuzz values.
const canaryPrefix = "nuclei"

// extractCanaryFromValue extracts the canary from the fuzz-generated value.
// The canary is the "nuclei" prefix followed by 8 random characters.
func extractCanaryFromValue(value string) string {
	idx := strings.Index(value, canaryPrefix)
	if idx < 0 {
		return ""
	}
	end := idx + len(canaryPrefix) + 8 // "nuclei" + 8 random chars
	if end > len(value) {
		return ""
	}
	return value[idx:end]
}

// Analyze detects XSS vulnerabilities by:
// 1. Checking for canary reflection in the initial response
// 2. Detecting the HTML context of the reflection
// 3. Replaying context-appropriate payloads to verify exploitability
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	// Extract canary from the generated request's value to avoid
	// race conditions with shared AnalyzerParameters map.
	canary := extractCanaryFromValue(options.FuzzGenerated.Value)
	if canary == "" {
		return false, "", nil
	}

	body := options.ResponseBody
	if body == "" {
		return false, "", nil
	}

	// Check Content-Type - only analyze HTML responses
	if !isHTMLResponse(options.ResponseHeaders) {
		return false, "", nil
	}

	// Check if canary is reflected at all (case-insensitive precheck)
	if !strings.Contains(strings.ToLower(body), strings.ToLower(canary)) {
		return false, "", nil
	}

	// Detect reflection contexts using the HTML tokenizer
	reflections := DetectReflections(body, canary)
	if len(reflections) == 0 {
		return false, "", nil
	}

	// Compute character survival per-reflection, filter non-viable ones,
	// then pick the best viable reflection.
	type viableReflection struct {
		reflection *ReflectionInfo
		chars      CharacterSet
	}
	var viable []viableReflection
	for i := range reflections {
		r := &reflections[i]
		if r.Context == ContextNone {
			continue
		}
		chars := detectCharacterSurvival(body, canary)
		payloads := selectPayloads(r, chars)
		if len(payloads) > 0 {
			viable = append(viable, viableReflection{reflection: r, chars: chars})
		}
	}
	if len(viable) == 0 {
		return false, "", nil
	}

	// Pick the best viable reflection by priority
	best := viable[0]
	for _, v := range viable[1:] {
		if v.reflection.Context.priority() > best.reflection.Context.priority() {
			best = v
		}
	}

	// Select payloads appropriate for the detected context
	payloads := selectPayloads(best.reflection, best.chars)
	if len(payloads) == 0 {
		return false, "", fmt.Errorf("no suitable payloads for context %s", best.reflection.Context)
	}

	// Replay with context-appropriate payloads
	for _, payload := range payloads {
		matched, details, err := a.replayAndVerify(options, payload, best.reflection)
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

// maxReplayBodySize limits the replay response body read to 5 MB.
const maxReplayBodySize = 5 * 1024 * 1024

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

	// Restore original value on every exit path (including Rebuild errors)
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

	// Verify the replay response is HTML before checking for reflection
	if !isHTMLResponse(resp.Header) {
		return false, "", nil
	}

	// Use bounded reader to avoid unbounded memory consumption
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxReplayBodySize))
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

		if hasCSP(options.ResponseHeaders) {
			details += " [note: CSP header present, may limit exploitability]"
		}

		return true, details, nil
	}

	return false, "", nil
}

// isHTMLResponse checks if the Content-Type indicates an HTML response.
// Accepts both map[string][]string and http.Header (which is the same type).
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

// detectCharacterSurvival checks which XSS-critical characters survived server-side encoding.
// Each character is tested independently against the canary to avoid cascading dependencies.
func detectCharacterSurvival(body string, canary string) CharacterSet {
	return CharacterSet{
		LessThan:     strings.Contains(body, canary+"<"),
		GreaterThan:  strings.Contains(body, canary+">"),
		DoubleQuote:  strings.Contains(body, canary+`"`),
		SingleQuote:  strings.Contains(body, canary+`'`),
		ForwardSlash: strings.Contains(body, canary+"/"),
	}
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

	case ContextNonExecutableScript:
		// Non-executable script blocks (application/json, etc.) can still be
		// broken out of with </script> tag injection.
		candidates = []string{
			`</script><img src=x onerror=alert(1)>`,
		}

	case ContextScriptComment:
		// Marker is inside a JS comment or regex literal — not directly executable.
		// The only viable attack is breaking out of the <script> block entirely.
		if chars.LessThan && chars.GreaterThan {
			candidates = []string{
				`</script><img src=x onerror=alert(1)>`,
			}
		}
	}

	return candidates
}
