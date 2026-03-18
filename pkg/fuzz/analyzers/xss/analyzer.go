package xss

import (
	"fmt"
	"strings"

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
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	if options.FuzzGenerated.OriginalPayload == "" {
		return false, "", nil
	}

	// Get the response body from the fuzzed request
	resp := options.FuzzGenerated.Request.Response
	if resp == nil {
		return false, "", nil
	}

	// Read response body
	bodyBytes, err := options.FuzzGenerated.Request.BodyBytes()
	if err != nil {
		return false, "", nil
	}

	responseBody := string(bodyBytes)

	// Check if payload is reflected in response (case-insensitive)
	if !strings.Contains(strings.ToLower(responseBody), strings.ToLower(options.FuzzGenerated.OriginalPayload)) {
		return false, "", nil
	}

	// Classify the context of the reflection
	ctx := ClassifyContext(responseBody, options.FuzzGenerated.OriginalPayload)

	// Determine vulnerability based on context
	isVulnerable := false
	reason := ""

	switch ctx {
	case ContextScript:
		// JavaScript context is vulnerable
		isVulnerable = true
		reason = "Payload reflected in executable JavaScript context"
	case ContextAttribute:
		// Attribute context may be vulnerable (requires event handlers)
		isVulnerable = true
		reason = "Payload reflected in HTML attribute context"
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
		gologger.Verbose().Msgf("[%s] %s", a.Name(), reason)
	}

	return isVulnerable, reason, nil
}
