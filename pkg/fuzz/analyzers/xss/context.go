// Package xss provides reflection context analysis for XSS detection
// in the nuclei fuzzing engine.
//
// When a reflection is found during fuzzing, this package determines WHERE
// in the HTML the reflection occurs and returns context-appropriate payloads.
package xss

import "fmt"

// XSSContext represents where in an HTML document a reflected value appears.
// The context determines which XSS payloads are viable.
type XSSContext int

const (
	ContextUnknown XSSContext = iota // could not determine context

	// HTML document structure contexts
	ContextHTMLBody // bare text between tags: <p>MARKER</p>
	ContextComment  // HTML comment: <!-- MARKER -->

	// Attribute contexts — quote style matters for escaping
	ContextAttributeDouble   // double-quoted: <tag attr="MARKER">
	ContextAttributeSingle   // single-quoted: <tag attr='MARKER'>
	ContextAttributeUnquoted // unquoted: <tag attr=MARKER>

	// Special attribute contexts
	ContextAttributeURL   // URL attribute (href/src/action/…): <a href="MARKER">
	ContextAttributeEvent // event handler: <div onclick="MARKER">
	ContextAttributeStyle // inline style: <span style="MARKER">

	// Script contexts
	ContextScript     // executable <script> block or javascript: URI that executes
	ContextScriptData // non-executable <script> (type="application/json", etc.)

	// Style block
	ContextStyle // <style> block

	// Structured data contexts
	ContextJSON     // inside a JSON value (in a script block)
	ContextTemplate // inside a JS template literal `…${MARKER}…`

	// Special contexts
	ContextCDATA  // inside CDATA section: <![CDATA[MARKER]]>
	ContextSrcDoc // inside srcdoc="" attribute (treated as nested HTML)
)

// contextNames maps each XSSContext value to its human-readable name.
var contextNames = map[XSSContext]string{
	ContextUnknown:          "Unknown",
	ContextHTMLBody:         "HTMLBody",
	ContextComment:          "Comment",
	ContextAttributeDouble:  "AttributeDouble",
	ContextAttributeSingle:  "AttributeSingle",
	ContextAttributeUnquoted: "AttributeUnquoted",
	ContextAttributeURL:     "AttributeURL",
	ContextAttributeEvent:   "AttributeEvent",
	ContextAttributeStyle:   "AttributeStyle",
	ContextScript:           "Script",
	ContextScriptData:       "ScriptData",
	ContextStyle:            "Style",
	ContextJSON:             "JSON",
	ContextTemplate:         "Template",
	ContextCDATA:            "CDATA",
	ContextSrcDoc:           "SrcDoc",
}

// String returns the human-readable name of the XSS context.
func (c XSSContext) String() string {
	if name, ok := contextNames[c]; ok {
		return name
	}
	return fmt.Sprintf("XSSContext(%d)", int(c))
}

// Severity returns an exploitation difficulty rating for the context.
// Lower is easier to exploit.
type Severity int

const (
	SeverityHigh   Severity = 1 // trivially exploitable
	SeverityMedium Severity = 2 // exploitable with some conditions
	SeverityLow    Severity = 3 // harder to exploit
)

// XSSResult describes a single reflected instance and how to exploit it.
type XSSResult struct {
	// Context is the classified HTML context for this reflection.
	Context XSSContext

	// Confidence is a 0.0–1.0 score indicating how certain the classification is.
	Confidence float64

	// Payloads contains ordered exploit candidates (most likely first).
	Payloads []string

	// BreakoutSeq is the minimal sequence to break out of the current context.
	BreakoutSeq string

	// Explanation is a human-readable description of why this context was chosen.
	Explanation string

	// QuoteChar holds the quote character used in the attribute (" or '), if applicable.
	QuoteChar string

	// AttributeName is the name of the HTML attribute, if applicable.
	AttributeName string

	// TagName is the surrounding HTML tag name, if applicable.
	TagName string

	// IsExecutableSink is true when the context directly executes JavaScript
	// without needing additional breakout (e.g. script block, event handler,
	// javascript: URI in an executable sink).
	IsExecutableSink bool
}
