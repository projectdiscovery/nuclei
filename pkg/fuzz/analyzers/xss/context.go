package xss

import (
	"strings"

	"golang.org/x/net/html"
)

// ContextType represents the XSS reflection context
type ContextType string

const (
	// ContextHTMLText represents HTML text content
	ContextHTMLText ContextType = "html-text"
	// ContextAttribute represents quoted attribute value
	ContextAttribute ContextType = "attribute"
	// ContextAttributeUnquoted represents unquoted attribute value
	ContextAttributeUnquoted ContextType = "attribute-unquoted"
	// ContextScript represents JavaScript context
	ContextScript ContextType = "script"
	// ContextScriptString represents string within JavaScript
	ContextScriptString ContextType = "script-string"
	// ContextStyle represents CSS context
	ContextStyle ContextType = "style"
	// ContextHTMLComment represents HTML comment
	ContextHTMLComment ContextType = "html-comment"
	// ContextJSON represents JSON data in script tag
	ContextJSON ContextType = "json"
	// ContextJavascriptURI represents javascript: URI scheme
	ContextJavascriptURI ContextType = "javascript-uri"
	// ContextSrcdoc represents srcdoc attribute HTML injection
	ContextSrcdoc ContextType = "srcdoc"
	// ContextNone represents no reflection
	ContextNone ContextType = "none"
)

// ContextAnalyzer analyzes HTML response for XSS contexts
type ContextAnalyzer struct {
	tokenizer *html.Tokenizer
}

// NewContextAnalyzer creates a new context analyzer
func NewContextAnalyzer() *ContextAnalyzer {
	return &ContextAnalyzer{}
}

// AnalyzeContext analyzes the HTML response and determines the XSS context
func (a *ContextAnalyzer) AnalyzeContext(response string, canary string) (ContextType, error) {
	a.tokenizer = html.NewTokenizer(strings.NewReader(response))
	
	for {
		tt := a.tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}
		
		token := a.tokenizer.Token()
		
		// Check for javascript: URI (Issue #7086)
		if a.isJavascriptURI(token) {
			return ContextJavascriptURI, nil
		}
		
		// Check for JSON script block (Issue #7086)
		if a.isJSONScript(token) {
			return ContextJSON, nil
		}
		
		// Check for srcdoc attribute (Issue #7086)
		if a.isSrcdoc(token) {
			return ContextSrcdoc, nil
		}
		
		// Check if canary is in this token (case-insensitive for Issue #7086)
		if a.containsCanary(token, canary) {
			return a.classifyToken(token), nil
		}
	}
	
	return ContextNone, nil
}

// isJavascriptURI checks if token represents a javascript: URI
func (a *ContextAnalyzer) isJavascriptURI(token html.Token) bool {
	// Check href, src, action attributes for javascript: scheme
	for _, attr := range token.Attr {
		if attr.Key == "href" || attr.Key == "src" || attr.Key == "action" {
			value := strings.TrimSpace(attr.Val)
			// Case-insensitive check for javascript: URI
			if strings.HasPrefix(strings.ToLower(value), "javascript:") {
				return true
			}
		}
	}
	return false
}

// isJSONScript checks if token is a JSON script block
func (a *ContextAnalyzer) isJSONScript(token html.Token) bool {
	if token.Data == "script" {
		for _, attr := range token.Attr {
			if attr.Key == "type" {
				typeVal := strings.ToLower(strings.TrimSpace(attr.Val))
				// JSON script types should not be treated as executable
				if typeVal == "application/json" || 
				   typeVal == "application/ld+json" ||
				   typeVal == "application/geo+json" {
					return true
				}
			}
		}
	}
	return false
}

// isSrcdoc checks if token has srcdoc attribute
func (a *ContextAnalyzer) isSrcdoc(token html.Token) bool {
	if token.Data == "iframe" || token.Data == "embed" || token.Data == "object" {
		for _, attr := range token.Attr {
			if attr.Key == "srcdoc" {
				return true
			}
		}
	}
	return false
}

// containsCanary checks if token contains the canary string (case-insensitive)
func (a *ContextAnalyzer) containsCanary(token html.Token, canary string) bool {
	tokenStr := token.String()
	// Case-insensitive check for Issue #7086
	return strings.Contains(strings.ToLower(tokenStr), strings.ToLower(canary))
}

// classifyToken classifies the token into appropriate context
func (a *ContextAnalyzer) classifyToken(token html.Token) ContextType {
	switch token.Type {
	case html.TextToken:
		return ContextHTMLText
	case html.SelfClosingTagToken, html.StartTagToken:
		return ContextAttribute
	case html.EndTagToken:
		return ContextHTMLText
	default:
		return ContextNone
	}
}
