package context

import (
	"bytes"
	"strings"

	"golang.org/x/net/html"
)

// ContextType represents the HTML context where the payload was reflected
type ContextType int

const (
	ContextUnknown ContextType = iota
	ContextHTMLBody
	ContextAttributeName
	ContextAttributeValueDoubleQuote
	ContextAttributeValueSingleQuote
	ContextAttributeValueUnquoted
	ContextScript
	ContextStyle
	ContextComment
	ContextRCDATA // textarea, title, no-script, etc.
)

func (c ContextType) String() string {
	switch c {
	case ContextHTMLBody:
		return "ContextHTMLBody"
	case ContextAttributeName:
		return "ContextAttributeName"
	case ContextAttributeValueDoubleQuote:
		return "ContextAttributeValueDoubleQuote"
	case ContextAttributeValueSingleQuote:
		return "ContextAttributeValueSingleQuote"
	case ContextAttributeValueUnquoted:
		return "ContextAttributeValueUnquoted"
	case ContextScript:
		return "ContextScript"
	case ContextStyle:
		return "ContextStyle"
	case ContextComment:
		return "ContextComment"
	case ContextRCDATA:
		return "ContextRCDATA"
	default:
		return "ContextUnknown"
	}
}

// AnalysisResult holds the verdict of the context analysis
type AnalysisResult struct {
	Vulnerable bool
	Context    ContextType
	Reason     string
}

// Analyze processes the response body to determine if the payload is executable
func Analyze(body []byte, payload string) AnalysisResult {
	// Fast Path: Optimization to avoid parsing if payload isn't present
	if !bytes.Contains(body, []byte(payload)) {
		return AnalysisResult{Vulnerable: false, Context: ContextUnknown}
	}

	tokenizer := html.NewTokenizer(bytes.NewReader(body))

	// State tracking variables
	var insideScript bool
	var insideStyle bool
	var insideTextarea bool

	for {
		tokenType := tokenizer.Next()
		// Get raw token bytes once
		rawToken := tokenizer.Raw()

		switch tokenType {
		case html.ErrorToken:
			// End of document or error
			return AnalysisResult{Vulnerable: false, Context: ContextUnknown}

		case html.StartTagToken:
			// Check if payload is in the raw tag, but careful about attributes
			// If payload corresponds to the tag itself (e.g. "<h1>"), we should catch it here.
			// But we also handle attributes separately.

			// If the payload contains the tag name, and we are here, it's likely vulnerable HTML injection.
			// Example: payload="<h1>", raw="<h1>" -> Vulnerable.
			// Example: payload="x", raw="<div x>" (attr) -> Handled in attr logic.

			tagName, hasAttr := tokenizer.TagName()
			tagStr := string(tagName)

			// Fast check: if payload is in this tag
			if bytes.Contains(rawToken, []byte(payload)) {
				// If we are inside RCDATA/Script (from previous implementation), this wouldn't trigger StartTag
				// unless it broke out.
				// Wait, if insideScript is true, does tokenizer emit StartTag?
				// No, the html tokenizer should handle script data differently unless it encounters </script>.

				// However, standard tokenizer logic:
				// If we see a StartTagToken, it means we satisfy conditions to be a tag.

				// Case: Payload is "<h1>"
				// rawToken is "<h1>"
				// It's a StartTag. Vulnerable.

				// Case: Payload is "onmouseover"
				// rawToken is "<div onmouseover>"
				// It's a StartTag. Vulnerable (Attribute Name).

				// We should let the specific checks below refine the context, but if we don't match below,
				// and validation implies "It became a tag", we should default to HTMLBody vulnerability?

				// But let's look at existing logic.
			}

			// Track state for RCDATA/Script blocks
			if tagStr == "script" {
				insideScript = true
			}
			if tagStr == "style" {
				insideStyle = true
			}
			if tagStr == "textarea" {
				insideTextarea = true
			}

			if hasAttr {
				// Check if payload is in attributes
				// Logic: Iterate attributes using tokenizer.TagAttr()
				// If payload found, check quoting style vs payload content
				attrKey, attrVal, moreAttr := tokenizer.TagAttr()
				for {
					if strings.Contains(string(attrKey), payload) {
						return AnalysisResult{Vulnerable: true, Context: ContextAttributeName, Reason: "Payload in attribute name"}
					}
					if strings.Contains(string(attrVal), payload) {
						return AnalysisResult{Vulnerable: verifyAttributeContext(string(attrVal), payload), Context: ContextAttributeValueDoubleQuote, Reason: "Payload in attribute value"}
					}
					if !moreAttr {
						break
					}
					attrKey, attrVal, moreAttr = tokenizer.TagAttr()
				}

				// If we are here, hasAttr was true, but payload wasn't found in attributes logic?
				// Example: payload="<img src=x>"
				// rawToken might be "<img src=x>"
				// Attr key "src", val "x".
				// Payload "<img src=x>" is NOT in "src" or "x".
				// So the loop misses it.

				// But bytes.Contains(rawToken, payload) would be true!
				// So if we found it in rawToken but NOT in attributes, it means the payload *constructed* the tag+attributes.
				// This is definitely HTML injection.
				if bytes.Contains(rawToken, []byte(payload)) {
					return AnalysisResult{Vulnerable: true, Context: ContextHTMLBody, Reason: "Payload reflected as tag with attributes"}
				}
			} else {
				// If no attributes, and payload is in rawToken, it means the payload formed the tag itself.
				if bytes.Contains(rawToken, []byte(payload)) {
					return AnalysisResult{Vulnerable: true, Context: ContextHTMLBody, Reason: "Payload reflected as tag"}
				}
			}

		case html.EndTagToken:
			tagName, _ := tokenizer.TagName()
			tagStr := string(tagName)

			// Check for breakout via closing tag
			// If we were inside a special block, and this tag closes it, and the payload *contains* this closing tag,
			// it's a confirmed breakout.
			if (insideScript && tagStr == "script") ||
				(insideStyle && tagStr == "style") ||
				(insideTextarea && tagStr == "textarea") {
				if strings.Contains(payload, "</"+tagStr) {
					ctx := ContextRCDATA
					if insideScript {
						ctx = ContextScript
					}
					// Only Textarea/Title are strictly RCDATA. Style is Rawtext?
					// ContextRCDATA covers them for our enum purposes.
					return AnalysisResult{Vulnerable: true, Context: ctx, Reason: "Breakout via enclosing tag"}
				}
			}

			if tagStr == "script" {
				insideScript = false
			}
			if tagStr == "style" {
				insideStyle = false
			}
			if tagStr == "textarea" {
				insideTextarea = false
			}

		case html.TextToken:
			text := tokenizer.Text()
			if bytes.Contains(text, []byte(payload)) {
				if insideScript {
					// Check for JS String Breakout using the surrounding text
					return verifyScriptContext(string(text), payload)
				}
				if insideStyle || insideTextarea {
					// Usually safe unless closing tag is present (handled in EndTagToken or here if partial)
					tag := "textarea"
					if insideStyle {
						tag = "style"
					}
					if strings.Contains(payload, "</"+tag) {
						return AnalysisResult{Vulnerable: true, Context: ContextRCDATA, Reason: "RCDATA breakout"}
					}
					return AnalysisResult{Vulnerable: false, Context: ContextRCDATA, Reason: "Reflected in RCDATA without breakout"}
				}

				// HTML Body Context
				// If we find the payload in a TextToken, it means it failed to parse as a StartTag.
				// Therefore it is treated as safe text or escaped text.
				if isEscaped(string(text), payload) {
					return AnalysisResult{Vulnerable: false, Context: ContextHTMLBody, Reason: "Reflected in body but escaped (TextContext)"}
				}
				return AnalysisResult{Vulnerable: true, Context: ContextHTMLBody, Reason: "Reflected in body unescaped"}
			}

		case html.CommentToken:
			// Use Raw() to catch breakouts like "-->" which might be part of the delimiter
			if bytes.Contains(rawToken, []byte(payload)) {
				if strings.Contains(payload, "-->") {
					return AnalysisResult{Vulnerable: true, Context: ContextComment, Reason: "Comment breakout"}
				}
				return AnalysisResult{Vulnerable: false, Context: ContextComment, Reason: "Reflected in comment"}
			}
		}
	}
}

// verifyScriptContext determines if payload inside script tag is executable
func verifyScriptContext(text string, payload string) AnalysisResult {
	// Check if the payload is inside quotes in the text
	// Simple heuristic: count occurrences of " and ' before the payload

	idx := strings.Index(text, payload)
	if idx == -1 {
		// Should not happen if bytes.Contains passed
		return AnalysisResult{Vulnerable: false, Context: ContextScript, Reason: "Payload not found in text"}
	}

	prefix := text[:idx]
	doubleQuotes := strings.Count(prefix, "\"") - strings.Count(prefix, "\\\"") // Subtract escaped? Crude.
	singleQuotes := strings.Count(prefix, "'") - strings.Count(prefix, "\\'")

	inDouble := doubleQuotes%2 != 0
	inSingle := singleQuotes%2 != 0

	// If not in quotes, it's code execution (Vulnerable)
	// UNLESS the payload itself IS the code and it's valid?
	// If we are NOT in string, any injection is dangerous code injection.
	if !inDouble && !inSingle {
		return AnalysisResult{Vulnerable: true, Context: ContextScript, Reason: "Reflected in script (Code Context)"}
	}

	// If payload contains quotes that might break out of the identified context
	if inDouble && strings.Contains(payload, "\"") {
		return AnalysisResult{Vulnerable: true, Context: ContextScript, Reason: "Double quote breakout"}
	}
	if inSingle && strings.Contains(payload, "'") {
		return AnalysisResult{Vulnerable: true, Context: ContextScript, Reason: "Single quote breakout"}
	}

	// If inside string and no quotes in payload, it's safe.
	// Even if it has (); it is strings.

	return AnalysisResult{Vulnerable: false, Context: ContextScript, Reason: "Reflected in script string"}
}

// verifyAttributeContext checks if payload breaks out of attribute
func verifyAttributeContext(attrVal string, payload string) bool {
	// If payload contains quotes, assume it might break out.
	// In a real browser parser, we'd know if it was single or double quoted.
	// Here we assume if it has quotes it's potentially dangerous.
	if strings.Contains(payload, "\"") || strings.Contains(payload, "'") {
		return true
	}
	return false
}

// isEscaped checks if the payload is safe within a TextContext.
// Since the tokenizer classified it as TextToken (and not StartTag), it implies
// that any HTML-significant characters in the payload were not interpreted as tags.
func isEscaped(text string, payload string) bool {
	// If the payload is found in a TextToken, it means it didn't transition the parser state
	// to TagOpen. Thus, even if it contains "<script>", it remained text.
	// Therefore, it is safe.
	return true
}
