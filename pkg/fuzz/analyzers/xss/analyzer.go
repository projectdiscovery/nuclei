package xss

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
)

// Analyzer implements the xss_context fuzz analyzer.
type Analyzer struct{}

var _ analyzers.Analyzer = &Analyzer{}

func init() {
	analyzers.RegisterAnalyzer(AnalyzerName, &Analyzer{})
}

// Name returns the analyzer registry name.
func (a *Analyzer) Name() string {
	return AnalyzerName
}

// ApplyInitialTransformation injects the canary value and applies common
// payload transformations before the first fuzz request is sent.
func (a *Analyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	canary := DefaultCanary
	if params != nil {
		if v, ok := params["canary"].(string); ok && v != "" {
			canary = v
		}
	}
	data = strings.ReplaceAll(data, "[XSS_CANARY]", canary)
	return analyzers.ApplyPayloadTransformations(data)
}

// Analyze performs the full XSS detection pipeline:
//  1. Detect reflections of the canary marker in the response body
//  2. Sort by exploitation priority (script > event > attr > html > comment)
//  3. For each reflection context, select payloads filtered by available chars
//  4. Replay each payload and verify the response confirms exploitability
//  5. Fail fast on double-encoding or unicode escaping
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	if options == nil || options.ResponseBody == "" {
		return false, "", nil
	}

	marker := options.FuzzGenerated.Value
	if marker == "" {
		marker = options.FuzzGenerated.OriginalPayload
	}
	if marker == "" {
		return false, "", nil
	}

	// Fail fast: double-encoding or unicode escaping means the server
	// is aggressively sanitising and payloads are unlikely to work.
	if DetectDoubleEncoding(options.ResponseBody) || DetectUnicodeEscape(options.ResponseBody) {
		gologger.Verbose().Msgf("[%s] Double-encoding or unicode escape detected, skipping", a.Name())
		return false, "", nil
	}

	reflections := DetectReflections(options.ResponseBody, marker)
	if len(reflections) == 0 {
		gologger.Verbose().Msgf("[%s] No reflections found for marker", a.Name())
		return false, "", nil
	}

	gologger.Verbose().Msgf("[%s] Found %d reflection(s)", a.Name(), len(reflections))

	sort.SliceStable(reflections, func(i, j int) bool {
		return reflections[i].PriorityWeight < reflections[j].PriorityWeight
	})

	for _, ref := range reflections {
		if ref.Context == ContextUnknown {
			continue
		}

		payloads := SelectPayloads(ref, options.AnalyzerParameters)
		if len(payloads) == 0 {
			gologger.Verbose().Msgf("[%s] No usable payloads for context %s (chars filtered)", a.Name(), ref.Context)
			continue
		}

		gologger.Verbose().Msgf("[%s] context=%s, trying %d payload(s)", a.Name(), ref.Context, len(payloads))

		for _, payload := range payloads {
			ok, err := replayAndVerify(options, payload, ref.Context)
			if err != nil {
				gologger.Verbose().Msgf("[%s] Replay failed for payload %q: %v", a.Name(), payload, err)
				continue
			}
			if ok {
				details := fmt.Sprintf(
					"[xss_context] XSS confirmed: parameter=%s context=%s payload=%q attr=%s chars=<:%v >:%v ':%v \":%v /:%v `:%v (:%v =:%v",
					options.FuzzGenerated.Parameter,
					ref.Context.String(),
					payload,
					ref.AttributeName,
					ref.AvailableChars.LessThan,
					ref.AvailableChars.GreaterThan,
					ref.AvailableChars.SingleQuote,
					ref.AvailableChars.DoubleQuote,
					ref.AvailableChars.Slash,
					ref.AvailableChars.Backtick,
					ref.AvailableChars.Parenthesis,
					ref.AvailableChars.Equals,
				)
				gologger.Verbose().Msgf("[%s] %s", a.Name(), details)
				return true, details, nil
			}
		}
	}

	gologger.Verbose().Msgf("[%s] No exploitable XSS after verification", a.Name())
	return false, "", nil
}

// replayAndVerify sends a replay request with the candidate payload and checks
// whether the replay response confirms exploitability for the expected context.
func replayAndVerify(options *analyzers.Options, payload string, expected ContextType) (bool, error) {
	gr := options.FuzzGenerated
	if gr.Component == nil || options.HttpClient == nil {
		return false, fmt.Errorf("missing replay dependencies")
	}

	original := gr.Value
	if original == "" {
		original = gr.OriginalValue
	}

	if err := gr.Component.SetValue(gr.Key, payload); err != nil {
		return false, err
	}
	defer func() {
		if original != "" {
			_ = gr.Component.SetValue(gr.Key, original)
		}
	}()

	req, err := gr.Component.Rebuild()
	if err != nil {
		return false, err
	}

	resp, err := options.HttpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return false, err
	}

	return verifyReplayBody(string(body), payload, expected), nil
}

// verifyReplayBody applies context-specific confirmation checks to reduce false
// positives when validating replay responses.
func verifyReplayBody(body, payload string, expected ContextType) bool {
	switch expected {
	case ContextScriptBlock, ContextScriptStringDouble, ContextScriptStringSingle, ContextScriptTemplate:
		return strings.Contains(body, "alert(1)") || strings.Contains(body, "alert`1`")
	case ContextEventHandler:
		return strings.Contains(body, "alert(1)") ||
			strings.Contains(body, "alert`1`") ||
			strings.Contains(body, "confirm(1)") ||
			strings.Contains(body, "prompt(1)")
	case ContextAttributeDoubleQuoted, ContextAttributeSingleQuoted, ContextAttributeUnquoted:
		return strings.Contains(body, "onfocus=alert(1)") ||
			strings.Contains(body, "onmouseover=alert(1)") ||
			strings.Contains(body, "onerror=alert(1)")
	case ContextHTMLText, ContextRCDATA, ContextStyle:
		return (strings.Contains(body, "<svg") || strings.Contains(body, "<img") ||
			strings.Contains(body, "<script") || strings.Contains(body, "<math")) &&
			strings.Contains(body, "alert(1)")
	case ContextComment:
		return (strings.Contains(body, "<img") || strings.Contains(body, "<svg")) &&
			strings.Contains(body, "alert(1)")
	case ContextURLAttribute:
		return strings.Contains(body, "javascript:alert")
	default:
		return strings.Contains(body, payload)
	}
}
