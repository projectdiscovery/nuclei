package xss

import (
	"strings"

	"golang.org/x/net/html"
)

// ContextAnalyzer analyzes HTML context for XSS payloads
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
		
		// Check for javascript: URI
		if a.isJavascriptURI(token) {
			return ContextJavascriptURI, nil
		}
		
		// Check for JSON script block
		if a.isJSONScript(token) {
			return ContextJSON, nil
		}
		
		// Check if canary is in this token
		if strings.Contains(token.String(), canary) {
			return a.classifyToken(token), nil
		}
	}
	
	return ContextNone, nil
}

// isJavascriptURI checks if token represents a javascript: URI
// FIX: Handle bypass via tabs, newlines, carriage returns, null bytes, and HTML entities (CWE-79)
func (a *ContextAnalyzer) isJavascriptURI(token html.Token) bool {
	// Check href, src attributes for javascript: scheme
	for _, attr := range token.Attr {
		if attr.Key == "href" || attr.Key == "src" {
			// Normalize the value: remove all characters that browsers ignore in URI schemes
			value := normalizeJavascriptURI(attr.Val)
			if strings.HasPrefix(strings.ToLower(value), "javascript:") {
				return true
			}
		}
	}
	return false
}

// normalizeJavascriptURI removes all characters that browsers ignore in URI schemes
// This prevents bypass via tabs, newlines, carriage returns, null bytes, and HTML entities
// FIX for CWE-79: javascript: URI bypass via control characters
func normalizeJavascriptURI(value string) string {
	// Remove all whitespace, control characters, and null bytes
	// Browsers ignore: \t (0x09), \n (0x0A), \r (0x0D), \0 (0x00), space (0x20)
	value = strings.Map(func(r rune) rune {
		// Remove control characters (0x00-0x1F), space (0x20), and DEL (0x7F)
		if r <= 0x20 || r == 0x7F {
			return -1 // Remove this character
		}
		return r
	}, value)
	
	// Also handle common HTML entity encodings that browsers decode
	// e.g., &#x09; (tab), &#9; (tab), &#x0A; (newline)
	value = decodeHTMLEntities(value)
	
	return value
}

// decodeHTMLEntities decodes common HTML entities used in bypass attempts
func decodeHTMLEntities(value string) string {
	// Map of HTML entities to their characters (we remove them for security)
	entities := map[string]string{
		"&#x09;": "", "&#9;": "",   // tab - remove
		"&#x0A;": "", "&#10;": "",  // newline - remove
		"&#x0D;": "", "&#13;": "",  // carriage return - remove
		"&#x00;": "", "&#0;": "",   // null byte - remove
	}
	
	result := value
	for entity, replacement := range entities {
		result = strings.ReplaceAll(result, entity, replacement)
	}
	
	return result
}

// isJSONScript checks if token is a JSON script block
func (a *ContextAnalyzer) isJSONScript(token html.Token) bool {
	if token.Data == "script" {
		for _, attr := range token.Attr {
			if attr.Key == "type" {
				typeVal := strings.ToLower(strings.TrimSpace(attr.Val))
				if typeVal == "application/json" || typeVal == "application/ld+json" {
					return true
				}
			}
		}
	}
	return false
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
