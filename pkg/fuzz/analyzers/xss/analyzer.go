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

// Analyzer is an XSS analyzer for the fuzzer
type Analyzer struct{}

var _ analyzers.Analyzer = &Analyzer{}

func init() {
	analyzers.RegisterAnalyzer("xss", &Analyzer{})
}

// Name is the name of the analyzer
func (a *Analyzer) Name() string {
	return "xss"
}

// ApplyInitialTransformation applies the transformation to the initial payload.
// For XSS analyzer, this is mainly identity transformation with support for
// special payload tokens.
func (a *Analyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	// Support for XSS-specific payload tokens
	if strings.Contains(data, "[XSS]") {
		data = strings.ReplaceAll(data, "[XSS]", "nucleiXSScanary")
	}
	
	// Apply common payload transformations
	data = analyzers.ApplyPayloadTransformations(data)
	return data
}

// Analyze is the main function for the XSS analyzer
// It analyzes the response to determine if XSS vulnerability is present
// based on context classification
// FIX: Now uses FuzzGenerated.Value and executes the rebuilt fuzzed request
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	// FIX: Use FuzzGenerated.Value instead of OriginalPayload
	payload := options.FuzzGenerated.Value
	if payload == "" {
		return false, "", nil
	}

	// FIX: Execute the rebuilt fuzzed request instead of using cached response
	gr := options.FuzzGenerated
	if gr.Component == nil {
		return false, "", errors.New("fuzz component is nil")
	}

	// Rebuild the request with the payload
	rebuilt, err := gr.Component.Rebuild()
	if err != nil {
		return false, "", errors.Wrap(err, "could not rebuild request")
	}

	// Execute the rebuilt request
	resp, err := options.HttpClient.Do(rebuilt)
	if err != nil {
		return false, "", errors.Wrap(err, "could not send request")
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", errors.Wrap(err, "could not read response body")
	}

	responseBody := string(respBody)

	// Check if payload is reflected in response (case-insensitive)
	if !strings.Contains(strings.ToLower(responseBody), strings.ToLower(payload)) {
		return false, "", nil
	}

	// Classify the context of the reflection
	ctx := ClassifyContext(responseBody, payload)

	// Determine vulnerability based on context
	isVulnerable := false
	reason := ""
	requiresManualVerification := false

	switch ctx {
	case ContextScript:
		// JavaScript context is vulnerable
		isVulnerable = true
		reason = "Payload reflected in executable JavaScript context"
	case ContextAttribute:
		// FIX: Attribute context requires secondary validation for event handlers
		// Check if the attribute is an event handler
		if isEventHandlerAttribute(responseBody, payload) {
			isVulnerable = true
			reason = "Payload reflected in event handler attribute context"
		} else {
			// Mark as requiring manual verification for non-event-handler attributes
			requiresManualVerification = true
			isVulnerable = true
			reason = "Payload reflected in HTML attribute context (requires manual verification)"
		}
	case ContextHTML:
		// HTML context is vulnerable
		isVulnerable = true
		reason = "Payload reflected in HTML content"
	case ContextJSON:
		// JSON context is not vulnerable to XSS
		isVulnerable = false
		reason = "Payload reflected in JSON data (not executable)"
	case ContextHTMLInjection:
		// srcdoc and similar contexts allow full HTML injection
		isVulnerable = true
		reason = "Payload reflected in HTML injection context (srcdoc)"
	default:
		isVulnerable = true
		reason = fmt.Sprintf("Payload reflected in %s context", ctx.String())
	}

	if isVulnerable {
		if requiresManualVerification {
			gologger.Verbose().Msgf("[%s] %s", a.Name(), reason)
		} else {
			gologger.Verbose().Msgf("[%s] %s", a.Name(), reason)
		}
	}

	return isVulnerable, reason, nil
}

// isEventHandlerAttribute checks if the payload is in an event handler attribute
func isEventHandlerAttribute(responseBody, payload string) bool {
	lowerBody := strings.ToLower(responseBody)
	lowerPayload := strings.ToLower(payload)
	
	payloadIdx := strings.Index(lowerBody, lowerPayload)
	if payloadIdx == -1 {
		return false
	}
	
	// Look backward to find the attribute name
	beforePayload := responseBody[:payloadIdx]
	
	// Find the last = before the payload
	eqIdx := strings.LastIndex(beforePayload, "=")
	if eqIdx == -1 {
		return false
	}
	
	// Find the attribute name before the =
	beforeEq := beforePayload[:eqIdx]
	
	// Find the start of the attribute name (after whitespace or tag start)
	attrNameStart := -1
	for i := len(beforeEq) - 1; i >= 0; i-- {
		if beforeEq[i] == ' ' || beforeEq[i] == '\t' || beforeEq[i] == '\n' || beforeEq[i] == '<' {
			attrNameStart = i + 1
			break
		}
	}
	
	if attrNameStart == -1 {
		return false
	}
	
	attrName := strings.ToLower(beforeEq[attrNameStart:])
	
	// Check if it's an event handler (starts with "on")
	return strings.HasPrefix(attrName, "on")
}

// isHTMLResponse checks if the Content-Type indicates an HTML response
func isHTMLResponse(headers http.Header) bool {
	ct := headers.Get("Content-Type")
	if ct == "" {
		return true // assume HTML if no Content-Type
	}
	ctLower := strings.ToLower(ct)
	return strings.Contains(ctLower, "text/html") || strings.Contains(ctLower, "application/xhtml")
}
