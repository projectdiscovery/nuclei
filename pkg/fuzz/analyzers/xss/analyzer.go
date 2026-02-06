package xss

import (
	"fmt"
	"io"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
)

// Analyzer is an XSS context analyzer for the fuzzer
type Analyzer struct{}

var _ analyzers.Analyzer = &Analyzer{}

func init() {
	analyzers.RegisterAnalyzer(AnalyzerName, &Analyzer{})
}

// Name returns the name of the analyzer
func (a *Analyzer) Name() string {
	return AnalyzerName
}

// ApplyInitialTransformation applies the transformation to the initial payload
//
// It supports the below placeholders:
//   - [XSS_CANARY] => canary probe payload
//
// It also applies the standard payload transformations
// which includes [RANDNUM] and [RANDSTR]
func (a *Analyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	canary := DefaultCanary
	if c, ok := params["canary"].(string); ok && c != "" {
		canary = c
	}

	data = strings.ReplaceAll(data, "[XSS_CANARY]", canary)
	data = analyzers.ApplyPayloadTransformations(data)

	return data
}

func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	canary := DefaultCanary
	if c, ok := options.AnalyzerParameters["canary"].(string); ok && c != "" {
		canary = c
	}

	gologger.Verbose().Msgf("[%s] Starting XSS context analysis with canary: %q", a.Name(), canary)

	responseBody, err := a.sendRequest(options, canary)
	if err != nil {
		gologger.Verbose().Msgf("[%s] Error sending canary request: %v", a.Name(), err)
		return false, "", err
	}

	gologger.Verbose().Msgf("[%s] Received response of %d bytes", a.Name(), len(responseBody))

	reflections := DetectContexts(responseBody, canary)
	if len(reflections) == 0 {
		gologger.Verbose().Msgf("[%s] No reflections found", a.Name())
		return false, "", nil
	}

	gologger.Verbose().Msgf("[%s] Found %d reflection(s)", a.Name(), len(reflections))

	for i, reflection := range reflections {
		gologger.Verbose().Msgf("[%s] Reflection #%d: context=%s, position=%d",
			a.Name(), i+1, reflection.Context.String(), reflection.Position)

		payloads := SelectPayloads(reflection, options.AnalyzerParameters)
		gologger.Verbose().Msgf("[%s] Selected %d payload(s) for verification", a.Name(), len(payloads))

		for j, payload := range payloads {
			gologger.Verbose().Msgf("[%s] Trying payload #%d: %q", a.Name(), j+1, payload)

			verified, details := a.verifyXSS(options, payload, reflection, canary)
			if verified {
				gologger.Verbose().Msgf("[%s] XSS confirmed!", a.Name())
				return true, details, nil
			}
		}
	}

	gologger.Verbose().Msgf("[%s] No exploitable XSS found after verification", a.Name())
	return false, "", nil
}

// sendRequest sends an HTTP request with the given payload and returns the response body.
// It validates options, sets the payload value in the component, rebuilds the request,
// and executes it using the HTTP client. Response body is limited to 1MB.
func (a *Analyzer) sendRequest(options *analyzers.Options, payload string) (string, error) {
	if options == nil {
		return "", fmt.Errorf("invalid options: nil options")
	}

	gr := options.FuzzGenerated
	if gr.Component == nil {
		return "", fmt.Errorf("invalid options: nil component")
	}

	if options.HttpClient == nil {
		return "", fmt.Errorf("invalid options: nil http client")
	}

	if err := gr.Component.SetValue(gr.Key, payload); err != nil {
		return "", err
	}

	req, err := gr.Component.Rebuild()
	if err != nil {
		return "", err
	}

	resp, err := options.HttpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	limitReader := io.LimitReader(resp.Body, 1*1024*1024)
	body, err := io.ReadAll(limitReader)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// verifyXSS verifies that an XSS payload successfully landed in an exploitable context.
// It sends a verification request, checks if the payload appears unmodified in the response,
// validates the context matches expectations, and ensures critical characters are not encoded.
// Returns true and details string if XSS is confirmed, false otherwise.
func (a *Analyzer) verifyXSS(options *analyzers.Options, payload string, originalReflection ReflectionInfo, canary string) (bool, string) {
	responseBody, err := a.sendRequest(options, payload)
	if err != nil {
		return false, ""
	}

	if !strings.Contains(responseBody, payload) {
		return false, ""
	}

	payloadPos := strings.Index(responseBody, payload)
	if payloadPos == -1 {
		return false, ""
	}

	lookbackStart := max(0, payloadPos-contextLookbackSize)
	lookbackText := responseBody[lookbackStart:payloadPos]
	lookbackLower := strings.ToLower(lookbackText)

	commentStart := strings.LastIndex(lookbackLower, "<!--")
	commentEnd := strings.LastIndex(lookbackLower, "-->")
	if commentStart != -1 && (commentEnd == -1 || commentStart > commentEnd) {
		return false, ""
	}

	verifyContext := detectContextType(responseBody, payloadPos)

	if !isContextCompatible(verifyContext, originalReflection.Context) {
		gologger.Verbose().Msgf("[%s] Context mismatch: original=%s, verified=%s",
			a.Name(), originalReflection.Context.String(), verifyContext.String())
		return false, ""
	}

	if hasCriticalCharsEncoded(payload, responseBody, payloadPos) {
		gologger.Verbose().Msgf("[%s] Critical characters in payload were encoded", a.Name())
		return false, ""
	}

	details := fmt.Sprintf(
		"[xss_context] XSS confirmed in %s context at position %d. Canary: %q, Payload: %q, AvailableChars: <:%v >:%v ':%v \":%v /:%v",
		originalReflection.Context.String(),
		payloadPos,
		canary,
		payload,
		originalReflection.AvailableChars.LessThan,
		originalReflection.AvailableChars.GreaterThan,
		originalReflection.AvailableChars.SingleQuote,
		originalReflection.AvailableChars.DoubleQuote,
		originalReflection.AvailableChars.Slash,
	)

	return true, details
}

// hasCriticalCharsEncoded checks if critical XSS characters in the payload were HTML-encoded
// in the response. It examines the exact payload region (not surrounding text) to determine
// if characters like <, >, ", ' appear in their encoded forms (&lt;, &gt;, &quot;, &#39;).
// Returns true if any critical character from the payload appears encoded.
func hasCriticalCharsEncoded(payload, responseBody string, payloadPos int) bool {
	if payloadPos < 0 || payloadPos+len(payload) > len(responseBody) {
		return false
	}

	payloadInResponse := responseBody[payloadPos : payloadPos+len(payload)]

	criticalEncodings := map[string]string{
		"<":  "&lt;",
		">":  "&gt;",
		"\"": "&quot;",
		"'":  "&#39;",
	}

	for char, encoding := range criticalEncodings {
		if strings.Contains(payload, char) {
			if strings.Contains(payloadInResponse, encoding) {
				return true
			}
		}
	}

	return false
}

// isContextCompatible checks if the verification context is compatible with the original context.
// Exact matches are always compatible. Some contexts can evolve during exploitation:
//   - Attribute contexts (quoted/unquoted/URL) can break out to HTML body
//   - Script string context can break out to script block
//
// Returns true if contexts are compatible for XSS verification.
func isContextCompatible(verifyContext, originalContext ContextType) bool {
	if verifyContext == originalContext {
		return true
	}

	switch originalContext {
	case ContextHTMLAttributeQuoted, ContextHTMLAttributeUnquoted, ContextURLAttribute:
		return verifyContext == ContextHTMLBody
	case ContextScriptString:
		return verifyContext == ContextScriptBlock
	default:
		return false
	}
}
