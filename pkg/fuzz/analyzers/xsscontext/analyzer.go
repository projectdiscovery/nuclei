package xsscontext

import (
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
)

// xssContextAnalyzer analyzes HTML response to detect XSS context
type xssContextAnalyzer struct{}

// Name returns analyzer name
func (a *xssContextAnalyzer) Name() string {
	return "xss-context"
}

// ApplyInitialTransformation applies transformations before analysis
func (a *xssContextAnalyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	return analyzers.ApplyPayloadTransformations(data)
}

// Analyze determines if payload is reflected in dangerous HTML context
func (a *xssContextAnalyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	resp := options.FuzzGenerated.Response
	
	body := string(resp.Body)
	payload := options.FuzzGenerated.Payload
	
	// Check if our payload is reflected
	transPayload := analyzers.ApplyPayloadTransformations(payload)
	if !strings.Contains(body, transPayload) {
		return false, "payload not reflected", nil
	}
	
	// Detect context
	context := detectContext(body, transPayload)
	
	switch context {
	case "script":
		return true, "reflected in script context - high risk", nil
	case "attribute":
		return true, "reflected in HTML attribute - high risk", nil
	case "event":
		return true, "reflected in event handler - critical", nil
	case "url":
		return true, "reflected in URL context - high risk", nil
	case "comment":
		return true, "reflected in HTML comment", nil
	default:
		return true, "reflected in body", nil
	}
}

func detectContext(body, payload string) string {
	lowerBody := strings.ToLower(body)
	lowerPayload := strings.ToLower(payload)
	
	// Check for script context
	if strings.Contains(lowerBody, "<script") && strings.Contains(lowerBody, lowerPayload) {
		return "script"
	}
	
	// Check for event handlers
	eventHandlers := []string{"onerror", "onload", "onclick", "onmouseover", "onfocus", "onblur"}
	for _, evt := range eventHandlers {
		if strings.Contains(lowerBody, evt+"=") && strings.Contains(lowerBody, lowerPayload) {
			return "event"
		}
	}
	
	// Check for href attribute (URL context)
	if strings.Contains(lowerBody, "href=") {
		if strings.Contains(lowerBody, lowerPayload) {
			return "url"
		}
	}
	
	// Check for general attribute
	if strings.Contains(lowerBody, "="+lowerPayload) || strings.Contains(lowerBody, " "+lowerPayload) {
		return "attribute"
	}
	
	// Check for HTML comments
	if strings.Contains(lowerBody, "<!--") && strings.Contains(lowerBody, "-->") {
		if strings.Contains(lowerBody, lowerPayload) {
			return "comment"
		}
	}
	
	return "body"
}

func init() {
	analyzers.RegisterAnalyzer("xss-context", &xssContextAnalyzer{})
}
