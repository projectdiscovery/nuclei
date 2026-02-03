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

// Compile-time interface verification
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

	// Replace [XSS_CANARY] placeholder
	data = strings.ReplaceAll(data, "[XSS_CANARY]", canary)

	// Apply standard transformations ([RANDNUM], [RANDSTR])
	data = analyzers.ApplyPayloadTransformations(data)

	return data
}

// Analyze is the main function for the analyzer
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	// Get canary from parameters or use default
	canary := DefaultCanary
	if c, ok := options.AnalyzerParameters["canary"].(string); ok && c != "" {
		canary = c
	}

	gologger.Verbose().Msgf("[%s] Starting XSS context analysis with canary: %q", a.Name(), canary)

	// Step 1: Send canary request
	responseBody, err := a.sendRequest(options, canary)
	if err != nil {
		gologger.Verbose().Msgf("[%s] Error sending canary request: %v", a.Name(), err)
		return false, "", err
	}

	gologger.Verbose().Msgf("[%s] Received response of %d bytes", a.Name(), len(responseBody))

	// Step 2: Detect contexts
	reflections := DetectContexts(responseBody, canary)
	if len(reflections) == 0 {
		gologger.Verbose().Msgf("[%s] No reflections found", a.Name())
		return false, "", nil // No reflection found
	}

	gologger.Verbose().Msgf("[%s] Found %d reflection(s)", a.Name(), len(reflections))

	// Step 3: Try verification for each reflection
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

	// Set the payload value
	if err := gr.Component.SetValue(gr.Key, payload); err != nil {
		return "", err
	}

	// Rebuild request with new payload
	req, err := gr.Component.Rebuild()
	if err != nil {
		return "", err
	}

	// Send request
	resp, err := options.HttpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// Read response body (limit to 1MB to avoid memory issues)
	limitReader := io.LimitReader(resp.Body, 1*1024*1024)
	body, err := io.ReadAll(limitReader)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func (a *Analyzer) verifyXSS(options *analyzers.Options, payload string, originalReflection ReflectionInfo, canary string) (bool, string) {
	// Send verification request with XSS payload
	responseBody, err := a.sendRequest(options, payload)
	if err != nil {
		return false, ""
	}

	// Check if payload appears in response unmodified
	if !strings.Contains(responseBody, payload) {
		return false, ""
	}

	// For verification, we check if the payload appears in an exploitable position
	// We use a unique marker from the payload to verify context, not the full payload
	// which could contain HTML tags that confuse context detection

	// Find where the payload is reflected
	payloadPos := strings.Index(responseBody, payload)
	if payloadPos == -1 {
		return false, ""
	}

	// Get lookback text to determine context at payload position
	lookbackStart := max(0, payloadPos-500)
	lookbackText := responseBody[lookbackStart:payloadPos]
	lookbackLower := strings.ToLower(lookbackText)

	// Check if the payload is inside an HTML comment (not exploitable)
	commentStart := strings.LastIndex(lookbackLower, "<!--")
	commentEnd := strings.LastIndex(lookbackLower, "-->")
	if commentStart != -1 && (commentEnd == -1 || commentStart > commentEnd) {
		return false, ""
	}

	// Re-run context detection to verify payload landed in an exploitable context
	verifyContext := detectContextType(responseBody, payloadPos)

	// Check if the verification context is compatible with the original context
	if !isContextCompatible(verifyContext, originalReflection.Context) {
		gologger.Verbose().Msgf("[%s] Context mismatch: original=%s, verified=%s",
			a.Name(), originalReflection.Context.String(), verifyContext.String())
		return false, ""
	}

	// Check if critical characters in the payload were encoded
	if hasCriticalCharsEncoded(payload, responseBody, payloadPos) {
		gologger.Verbose().Msgf("[%s] Critical characters in payload were encoded", a.Name())
		return false, ""
	}

	// The payload was reflected unmodified, is not in a comment,
	// context is compatible, and critical chars are not encoded
	// This is considered a successful XSS verification

	// Build detailed match reason
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
func hasCriticalCharsEncoded(payload, responseBody string, payloadPos int) bool {
	// Ensure we have valid bounds
	if payloadPos < 0 || payloadPos+len(payload) > len(responseBody) {
		return false
	}

	// Extract the exact region in response that corresponds to the payload
	payloadInResponse := responseBody[payloadPos : payloadPos+len(payload)]

	// Check for common HTML encodings of critical characters
	criticalEncodings := map[string]string{
		"<":  "&lt;",
		">":  "&gt;",
		"\"": "&quot;",
		"'":  "&#39;",
	}

	// Check if any critical char in payload appears encoded in the response
	for char, encoding := range criticalEncodings {
		if strings.Contains(payload, char) {
			// If the payload contains this char, check if it appears encoded
			// in the actual payload region of the response
			if strings.Contains(payloadInResponse, encoding) {
				return true
			}
		}
	}

	return false
}

// isContextCompatible checks if contexts are compatible
func isContextCompatible(verifyContext, originalContext ContextType) bool {
	// Exact match is always compatible
	if verifyContext == originalContext {
		return true
	}

	// Some contexts can evolve (e.g., attribute -> body if we break out)
	switch originalContext {
	case ContextHTMLAttributeQuoted, ContextHTMLAttributeUnquoted, ContextURLAttribute:
		// Attribute breakout can lead to body context
		return verifyContext == ContextHTMLBody
	case ContextScriptString:
		// Script string breakout can lead to script block
		return verifyContext == ContextScriptBlock
	default:
		return false
	}
}
