// Package xss provides reflection context analysis for XSS detection
// in the nuclei fuzzing engine.
package xss

import "fmt"

// XSSContext represents where in an HTML document a reflected value appears.
type XSSContext int

const (
	ContextUnknown            XSSContext = iota // could not determine context
	ContextHTMLBody                             // text content between tags
	ContextHTMLAttribute                        // generic attribute value
	ContextHTMLAttributeURL                     // URL attr (href, src, action, etc.)
	ContextHTMLAttributeEvent                   // event handler attr (onclick, onerror, etc.)
	ContextScript                               // executable <script> or javascript: URI
	ContextScriptData                           // non-executable <script> (e.g. type="application/json")
	ContextStyle                                // <style> block or style="" attribute
	ContextComment                              // HTML comment
)

// contextNames maps each XSSContext value to its human-readable name.
var contextNames = map[XSSContext]string{
	ContextUnknown:            "Unknown",
	ContextHTMLBody:           "HTMLBody",
	ContextHTMLAttribute:      "HTMLAttribute",
	ContextHTMLAttributeURL:   "HTMLAttributeURL",
	ContextHTMLAttributeEvent: "HTMLAttributeEvent",
	ContextScript:             "Script",
	ContextScriptData:         "ScriptData",
	ContextStyle:              "Style",
	ContextComment:            "Comment",
}

// String returns the name of the XSS context.
func (c XSSContext) String() string {
	if name, ok := contextNames[c]; ok {
		return name
	}
	return fmt.Sprintf("XSSContext(%d)", int(c))
}
