package xss

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
	// ContextNone represents no reflection
	ContextNone ContextType = "none"
)

// String returns string representation
func (c ContextType) String() string {
	return string(c)
}
