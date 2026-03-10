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
func (a *ContextAnalyzer) isJavascriptURI(token html.Token) bool {
	// Check href, src attributes for javascript: scheme
	for _, attr := range token.Attr {
		if attr.Key == "href" || attr.Key == "src" {
			value := strings.TrimSpace(attr.Val)
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
