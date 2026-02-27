// Package xss implements a context-aware XSS reflection analyzer for the
// nuclei fuzzing engine. It detects where user-controlled input is
// reflected in an HTTP response, classifies the surrounding HTML
// parsing context, selects payloads that can structurally achieve
// script execution in that context, and replays them to verify
// exploitability.
//
// The analyzer is registered under the name "xss_context" and can be
// used in fuzzing templates via the `analyzer` field:
//
//	analyzer:
//	  name: xss_context
//	  parameters:
//	    canary: "<custom_canary>"   # optional
//
// When no custom canary is provided, the analyzer generates one that
// includes special characters needed for character-survival detection.
package xss

import (
	"fmt"
	"io"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
)

// Analyzer implements the analyzers.Analyzer interface for XSS
// context detection and verification.
type Analyzer struct{}

var _ analyzers.Analyzer = &Analyzer{}

func init() {
	analyzers.RegisterAnalyzer("xss_context", &Analyzer{})
}

// Name returns the registered name of this analyzer.
func (a *Analyzer) Name() string {
	return "xss_context"
}

// defaultCanarySuffix contains characters whose survival we want to
// test. It is appended to the random marker so the reflection check
// can determine which chars survive server-side filtering.
const defaultCanarySuffix = `<>"'/`

// ApplyInitialTransformation replaces the [XSS_CANARY] placeholder
// in the payload template with a generated canary value. The canary
// consists of a random alphanumeric prefix (to avoid collisions with
// page content) plus special characters for character-survival testing.
//
// If the payload does not contain [XSS_CANARY], standard placeholder
// transformations ([RANDNUM], [RANDSTR]) are applied instead.
func (a *Analyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	data = analyzers.ApplyPayloadTransformations(data)

	if strings.Contains(data, "[XSS_CANARY]") {
		// Allow a custom canary via template parameters.
		canary := ""
		if params != nil {
			if v, ok := params["canary"]; ok {
				canary, _ = v.(string)
			}
		}
		if canary == "" {
			canary = "nxss" + randAlphaNum(6) + defaultCanarySuffix
		}
		data = strings.ReplaceAll(data, "[XSS_CANARY]", canary)
		if params != nil {
			params["xss_canary"] = canary
		}
	}
	return data
}

// Analyze inspects the HTTP response for reflected XSS vulnerabilities.
//
// High-level flow:
//  1. Extract the canary from analyzer parameters (set by
//     ApplyInitialTransformation).
//  2. Check if the canary is present in the response body.
//  3. Run the HTML tokenizer-based context detector to classify each
//     reflection point.
//  4. For each context, select payloads whose required characters
//     survived the server's filtering.
//  5. Replay each candidate payload through the original fuzz
//     component and verify the response confirms exploitability.
//  6. Return true with a descriptive reason string on the first
//     confirmed reflection, or false if nothing verifies.
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	// Retrieve the canary that ApplyInitialTransformation injected.
	canary := ""
	if options.AnalyzerParameters != nil {
		if v, ok := options.AnalyzerParameters["xss_canary"]; ok {
			canary, _ = v.(string)
		}
	}
	if canary == "" {
		return false, "", nil
	}

	body := options.ResponseBody
	if body == "" {
		return false, "", nil
	}

	// Quick check: is the canary reflected at all?
	if !strings.Contains(body, canary) {
		return false, "", nil
	}

	reflections := DetectReflections(body, canary)
	if len(reflections) == 0 {
		return false, "", nil
	}

	// For each reflection, try context-appropriate payloads.
	for _, ref := range reflections {
		payloads := SelectPayloads(ref.Context, ref.Chars)
		if len(payloads) == 0 {
			continue
		}

		for _, payload := range payloads {
			ok, err := replayAndVerify(options, payload, ref.Context)
			if err != nil {
				gologger.Verbose().Msgf("[%s] replay error for payload %q: %v", a.Name(), payload, err)
				continue
			}
			if ok {
				reason := fmt.Sprintf(
					"[xss_context] reflected XSS confirmed in %s context at position %d (payload: %s)",
					ref.Context, ref.Position, payload,
				)
				return true, reason, nil
			}
		}
	}

	return false, "", nil
}

// replayAndVerify sends the candidate payload through the original
// fuzz component (replacing the fuzzed value), reads the response, and
// checks whether the payload appears unencoded in the appropriate
// context. This reduces false positives that would occur if we only
// checked whether characters survive without verifying actual
// injection success.
func replayAndVerify(options *analyzers.Options, payload string, ctx ContextType) (bool, error) {
	gr := options.FuzzGenerated

	// Save the original value so we can restore the component after
	// replaying. This is important because other payloads or subsequent
	// analysis steps need the component in its original state.
	original := gr.Value
	if original == "" {
		original = gr.OriginalValue
	}
	needsRestore := original != "" || gr.Value != "" || gr.OriginalValue != ""
	defer func() {
		if needsRestore {
			_ = gr.Component.SetValue(gr.Key, original)
			_, _ = gr.Component.Rebuild()
		}
	}()

	if err := gr.Component.SetValue(gr.Key, payload); err != nil {
		return false, errors.Wrap(err, "could not set payload value")
	}

	rebuilt, err := gr.Component.Rebuild()
	if err != nil {
		return false, errors.Wrap(err, "could not rebuild request")
	}

	gologger.Verbose().Msgf("[%s] replaying payload %q to %s", "xss_context", payload, rebuilt.URL.String())

	resp, err := options.HttpClient.Do(rebuilt)
	if err != nil {
		return false, errors.Wrap(err, "replay request failed")
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, errors.Wrap(err, "could not read replay response")
	}

	return verifyReplayBody(string(respBody), payload, ctx), nil
}

// verifyReplayBody checks whether the payload string (or its critical
// components) appears in the response in a way that confirms
// exploitability. Simple string containment is the baseline; for
// specific contexts we look for structural indicators.
func verifyReplayBody(body, payload string, ctx ContextType) bool {
	if !strings.Contains(body, payload) {
		return false
	}

	// Context-specific sanity checks to weed out false positives
	// where the payload is present but not actually executable.
	switch ctx {
	case ContextHTMLText:
		// The injected tag must appear as-is (not entity-encoded).
		return strings.Contains(body, "<script>alert(1)</script>") ||
			strings.Contains(body, "onerror=alert(1)") ||
			strings.Contains(body, "onload=alert(1)") ||
			strings.Contains(body, "ontoggle=alert(1)")

	case ContextAttribute, ContextAttributeUnquoted:
		return strings.Contains(body, "onfocus=alert(1)") ||
			strings.Contains(body, "onmouseover=alert(1)") ||
			strings.Contains(body, "onload=alert(1)") ||
			strings.Contains(body, "<script>alert(1)</script>") ||
			strings.Contains(body, "<img") ||
			strings.Contains(body, "<svg")

	case ContextScript, ContextScriptString:
		return strings.Contains(body, "alert(1)") ||
			strings.Contains(body, "alert(document.domain)")

	case ContextHTMLComment:
		// The comment must have been closed by -->.
		return strings.Contains(body, "-->") &&
			(strings.Contains(body, "<script>alert(1)</script>") ||
				strings.Contains(body, "onerror=alert(1)"))

	case ContextStyle:
		return strings.Contains(body, "</style>") &&
			(strings.Contains(body, "<script>alert(1)</script>") ||
				strings.Contains(body, "onerror=alert(1)"))
	}

	// Fallback: the payload string is present verbatim.
	return true
}

// randAlphaNum generates a random alphanumeric string of length n.
// We reuse the shared random source from the analyzers package by
// calling the exported helper.
func randAlphaNum(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[analyzers.GetRandomInteger()%len(charset)]
	}
	return string(b)
}
