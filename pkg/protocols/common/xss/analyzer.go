package xss

import (
	"strings"
	"unicode"

	"golang.org/x/net/html"
)

// ContextType represents the type of XSS injection context.
// It defines the various contexts where XSS payloads can be injected in HTML content.
type ContextType int
type ContextType int

// Context type constants define the specific injection contexts that can be detected.
const (
	ContextUnknown ContextType = iota
	ContextHTMLText
	ContextHTMLAttribute
	ContextJavaScript
	ContextCSS
	ContextURL
	ContextScriptBlock
	ContextStyleBlock
)

// String returns the string representation of the context type
func (c ContextType) String() string {
	switch c {
	case ContextHTMLText:
		return "html-text"
	case ContextHTMLAttribute:
		return "html-attribute"
	case ContextJavaScript:
		return "javascript"
	case ContextCSS:
		return "css"
	case ContextURL:
		return "url"
	case ContextScriptBlock:
		return "script-block"
	case ContextStyleBlock:
		return "style-block"
	default:
		return "unknown"
	}
}

// XSSContextAnalyzer analyzes HTML content to detect XSS injection contexts.
// It provides methods to scan HTML documents and identify where XSS payloads
// can be injected and executed.
type XSSContextAnalyzer struct {
	payload string // The XSS payload string to search for
}
type XSSContextAnalyzer struct {
	payload string
}

// NewXSSContextAnalyzer creates a new XSS context analyzer
func NewXSSContextAnalyzer(payload string) *XSSContextAnalyzer {
	return &XSSContextAnalyzer{payload: payload}
}

// ContextAnalysis represents the analysis result for a specific context.
// It contains metadata about where and how an XSS payload was found,
// including the context type, location, and suggested payloads.
type ContextAnalysis struct {
	Type        ContextType // The type of XSS context detected
	Location    int         // Byte offset where payload was found
	Escaped     bool        // Whether the payload is HTML escaped
	Executable  bool        // Whether the payload can execute
	Confidence  float64     // Confidence score (0.0-1.0)
	Suggestions []string    // Recommended payloads for this context
}
type ContextAnalysis struct {
	Type        ContextType
	Location    int
	Escaped     bool
	Executable  bool
	Confidence  float64
	Suggestions []string
}

// Analyze analyzes the HTML content and returns the detected contexts.
// It scans the provided HTML document for the configured payload and returns
// a slice of ContextAnalysis structs describing all injection points found.
//
// The analysis covers:
// - HTML text content
// - HTML attributes (including URLs and event handlers)
// - JavaScript contexts
// - URL contexts with dangerous schemes
// - Script block content
// - Style block content
//
// Returns an empty slice if no contexts are detected.
func (a *XSSContextAnalyzer) Analyze(htmlContent string) []ContextAnalysis {
func (a *XSSContextAnalyzer) Analyze(htmlContent string) []ContextAnalysis {
	var contexts []ContextAnalysis
	
	// Check for payload in different contexts
	if ctx := a.analyzeHTMLContext(htmlContent); ctx != nil {
		contexts = append(contexts, *ctx)
	}
	
	if ctx := a.analyzeJavaScriptContext(htmlContent); ctx != nil {
		contexts = append(contexts, *ctx)
	}
	
	
	if ctx := a.analyzeURLContext(htmlContent); ctx != nil {
		contexts = append(contexts, *ctx)
	}
	
	return contexts
}

// analyzeHTMLContext analyzes HTML text and tag contexts to detect XSS injection points.
// It tokenizes the HTML content and checks for payload presence in text nodes,
// attributes, script blocks, and style blocks. Returns a ContextAnalysis if found.
// 
// The function handles:
// - Text content within HTML elements
// - Attribute values (including URL and event handler attributes)
// - Script block content
// - Style block content
func (a *XSSContextAnalyzer) analyzeHTMLContext(content string) *ContextAnalysis {
	tokenizer := html.NewTokenizer(strings.NewReader(content))
	
	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			break
		}
		
		switch tokenType {
		case html.TextToken:
			text := string(tokenizer.Text())
			if idx := strings.Index(text, a.payload); idx != -1 {
				return &ContextAnalysis{
					Type:       ContextHTMLText,
					Location:   tokenizer.Offset(),
					Escaped:    a.isEscaped(text, a.payload),
					Executable: !a.isEscaped(text, a.payload),
					Confidence: 0.9,
					Suggestions: a.getHTMLPayloads(),
				}
			}
			
		case html.StartTagToken, html.SelfClosingTagToken:
			tagName, hasAttr := tokenizer.TagName()
			if hasAttr {
				for {
					key, val, more := tokenizer.TagAttr()
					attrValue := string(val)
					
					if idx := strings.Index(attrValue, a.payload); idx != -1 {
						ctx := &ContextAnalysis{
							Location:   tokenizer.Offset(),
							Confidence: 0.85,
						}
						
						// Check for URL contexts
						if a.isURLAttribute(string(key)) {
							ctx.Type = ContextURL
							ctx.Executable = true
							ctx.Suggestions = a.getURLPayloads()
						} else if a.isEventHandler(string(key)) {
							ctx.Type = ContextJavaScript
							ctx.Executable = true
							ctx.Suggestions = a.getJavaScriptPayloads()
						} else {
							ctx.Type = ContextHTMLAttribute
							ctx.Executable = false
							ctx.Suggestions = a.getAttributePayloads()
						}
						
						return ctx
					}
					
					if !more {
						break
					}
				}
			}
			
			// Check for script blocks - don't return early, continue scanning
			if string(tagName) == "script" {
				if ctx := a.analyzeScriptBlock(tokenizer, content); ctx != nil {
					return ctx
				}
			}
			
			// Check for style blocks - don't return early, continue scanning
			if string(tagName) == "style" {
				if ctx := a.analyzeStyleBlock(tokenizer, content); ctx != nil {
					return ctx
				}
			}
		}
	}
	
	return nil
}

// analyzeJavaScriptContext analyzes JavaScript contexts to detect XSS injection points.
// It checks for payload presence in JavaScript string literals (double quotes, backticks, single quotes).
// Returns a ContextAnalysis if the payload is found within a JavaScript context.
// 
// This function detects:
// - Payloads in double-quoted strings
// - Payloads in template literals (backticks)
// - Payloads in single-quoted strings
func (a *XSSContextAnalyzer) analyzeJavaScriptContext(content string) *ContextAnalysis {
	// Check for payload in JavaScript contexts
	jsPatterns := []string{
		`"` + a.payload + `"`,
		"`" + a.payload + "`",
		"'" + a.payload + "'",
	}
	
	for _, pattern := range jsPatterns {
		if idx := strings.Index(content, pattern); idx != -1 {
			return &ContextAnalysis{
				Type:       ContextJavaScript,
				Location:   idx,
				Escaped:    false,
				Executable: true,
				Confidence: 0.95,
				Suggestions: a.getJavaScriptPayloads(),
			}
		}
	}
	
	return nil
}

// analyzeURLContext analyzes URL contexts to detect XSS injection points.
// It checks for payload presence in URL schemes like javascript:, data:, and vbscript:.
// Returns a ContextAnalysis if the payload is found within a URL context.
//
// This function detects dangerous URL schemes that could lead to XSS execution.
func (a *XSSContextAnalyzer) analyzeURLContext(content string) *ContextAnalysis {
	urlSchemes := []string{"javascript:", "data:", "vbscript:"}
	
	for _, scheme := range urlSchemes {
		if strings.Contains(content, scheme+a.payload) {
			idx := strings.Index(content, scheme+a.payload)
			return &ContextAnalysis{
				Type:       ContextURL,
				Location:   idx,
				Escaped:    false,
				Executable: true,
				Confidence: 0.95,
				Suggestions: a.getURLPayloads(),
			}
		}
	}
	
	return nil
}

// analyzeScriptBlock analyzes script block contexts to detect XSS injection points.
// It extracts the text content within <script> tags and checks for payload presence.
// Returns a ContextAnalysis if the payload is found within a script block.
func (a *XSSContextAnalyzer) analyzeScriptBlock(tokenizer *html.Tokenizer, content string) *ContextAnalysis {
	tokenType := tokenizer.Next()
	if tokenType == html.TextToken {
		text := string(tokenizer.Text())
		if idx := strings.Index(text, a.payload); idx != -1 {
			return &ContextAnalysis{
				Type:       ContextScriptBlock,
				Location:   tokenizer.Offset(),
				Escaped:    false,
				Executable: true,
				Confidence: 0.9,
				Suggestions: a.getScriptBlockPayloads(),
			}
		}
	}
	
	return nil
}

// analyzeStyleBlock analyzes style block contexts to detect XSS injection points.
// It extracts the text content within <style> tags and checks for payload presence.
// Returns a ContextAnalysis if the payload is found within a style block.
func (a *XSSContextAnalyzer) analyzeStyleBlock(tokenizer *html.Tokenizer, content string) *ContextAnalysis {
	tokenType := tokenizer.Next()
	if tokenType == html.TextToken {
		text := string(tokenizer.Text())
		if idx := strings.Index(text, a.payload); idx != -1 {
			return &ContextAnalysis{
				Type:       ContextStyleBlock,
				Location:   tokenizer.Offset(),
				Escaped:    false,
				Executable: true,
				Confidence: 0.85,
				Suggestions: a.getStyleBlockPayloads(),
			}
		}
	}
	
	return nil
}

// Helper functions provide utility methods for context detection and payload generation.

// isEscaped checks if the payload in the given text is HTML escaped.
// It looks for common HTML escape sequences like &lt;, &gt;, &quot;, and &#xx;.
// Returns true if the payload appears to be escaped, false otherwise.
func (a *XSSContextAnalyzer) isEscaped(text, payload string) bool {

func (a *XSSContextAnalyzer) isEscaped(text, payload string) bool {
	if strings.Contains(text, "&lt;") || strings.Contains(text, "&gt;") ||
		strings.Contains(text, "&quot;") || strings.Contains(text, "&#") {
		return true
	}
	return false
}

func (a *XSSContextAnalyzer) isURLAttribute(attrName string) bool {
	urlAttrs := map[string]bool{
		"href": true, "src": true, "action": true, "formaction": true,
		"data": true, "poster": true, "codebase": true, "cite": true,
		"background": true, "manifest": true, "icon": true, "ping": true,
		"longdesc": true,
	}
	return urlAttrs[attrName]
}

func (a *XSSContextAnalyzer) isEventHandler(attrName string) bool {
	return strings.HasPrefix(attrName, "on")
}

// Payload suggestion functions

func (a *XSSContextAnalyzer) getHTMLPayloads() []string {
	return []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"<iframe src=javascript:alert(1)>",
	}
}

func (a *XSSContextAnalyzer) getJavaScriptPayloads() []string {
	return []string{
		"';alert(1);//",
		"';alert(1);'",
		"\"><script>alert(1)</script>",
		"-alert(1)-",
	}
}

func (a *XSSContextAnalyzer) getAttributePayloads() []string {
	return []string{
		"\" onmouseover=alert(1) \"",
		"' onfocus=alert(1) autofocus='",
		"javascript:alert(1)",
	}
}

func (a *XSSContextAnalyzer) getURLPayloads() []string {
	return []string{
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"vbscript:msgbox(1)",
	}
}

func (a *XSSContextAnalyzer) getCSSPayloads() []string {
	return []string{
		"</style><script>alert(1)</script><style>",
		"body{background:url('javascript:alert(1)')}",
	}
}

func (a *XSSContextAnalyzer) getScriptBlockPayloads() []string {
	return []string{
		"';alert(1);//",
		"</script><script>alert(1)</script>",
		"-alert(1)-",
	}
}

func (a *XSSContextAnalyzer) getStyleBlockPayloads() []string {
	return []string{
		"</style><script>alert(1)</script><style>",
		"body{background:url('javascript:alert(1)')}",
	}
}

// GetSmartPayload returns the most appropriate payload based on context.
// It analyzes the provided context analyses and selects the payload with
// the highest confidence score. If multiple contexts have the same confidence,
// it returns the first suggestion from the highest confidence context.
//
// Returns the original payload if no contexts are provided or if no suggestions
// are available.
func (a *XSSContextAnalyzer) GetSmartPayload(contexts []ContextAnalysis) string {
func (a *XSSContextAnalyzer) GetSmartPayload(contexts []ContextAnalysis) string {
	if len(contexts) == 0 {
		return a.payload
	}
	
	var bestContext *ContextAnalysis
	for i := range contexts {
		if bestContext == nil || contexts[i].Confidence > bestContext.Confidence {
			bestContext = &contexts[i]
		}
	}
	
	if bestContext != nil && len(bestContext.Suggestions) > 0 {
		return bestContext.Suggestions[0]
	}
	
	return a.payload
}
