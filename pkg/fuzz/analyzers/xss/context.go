package xss

import (
	"strings"

	"golang.org/x/net/html"
)

// nonExecutableScriptTypes contains MIME types that make a <script> block
// a data block rather than executable JavaScript. Per the WHATWG HTML spec,
// only JavaScript MIME types (text/javascript and its legacy aliases) cause
// script execution. Everything else is treated as a data block.
var nonExecutableScriptTypes = map[string]struct{}{
	"application/json":       {},
	"application/ld+json":    {},
	"application/x-json":     {},
	"text/json":              {},
	"text/x-json":            {},
	"application/importmap+json": {},
	"speculationrules":       {},
	"text/template":          {},
	"application/x-template": {},
}

// isNonExecutableScriptType returns true if the script type attribute value
// indicates a non-executable data block.
func isNonExecutableScriptType(typeAttr string) bool {
	t := strings.TrimSpace(strings.ToLower(typeAttr))
	// Strip MIME parameters (e.g. "application/json; charset=utf-8")
	if idx := strings.IndexByte(t, ';'); idx >= 0 {
		t = strings.TrimSpace(t[:idx])
	}
	_, ok := nonExecutableScriptTypes[t]
	return ok
}

// isJavaScriptURI returns true when an attribute value contains a javascript:
// URI scheme (with optional leading C0 whitespace per the URL spec).
func isJavaScriptURI(attrVal string) bool {
	// Strip C0 control characters and ASCII whitespace that browsers skip
	// before the scheme (per WHATWG URL Standard § 4.1).
	stripped := strings.TrimFunc(attrVal, func(r rune) bool {
		return r <= 0x20
	})
	return strings.HasPrefix(strings.ToLower(stripped), "javascript:")
}

// DetectReflections parses the HTML body and returns all reflection contexts
// where the marker is found.
func DetectReflections(body string, marker string) []ReflectionInfo {
	// Fix #3: case-insensitive pre-check so reflections with transformed casing
	// are not silently discarded before the tokenizer runs.
	markerLower := strings.ToLower(marker)
	if !strings.Contains(strings.ToLower(body), markerLower) {
		return nil
	}

	var reflections []ReflectionInfo

	tokenizer := html.NewTokenizer(strings.NewReader(body))

	var tagStack []string
	inScript := false
	inStyle := false
	inRCDATA := false

	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}

		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			// Capture raw token text before consuming attributes
			rawToken := string(tokenizer.Raw())

			tn, hasAttr := tokenizer.TagName()
			tagName := string(tn)
			tagNameLower := strings.ToLower(tagName)

			if tt == html.StartTagToken {
				tagStack = append(tagStack, tagNameLower)
			}

			// Fix #2: For <script> tags, only mark as executable if the type
			// attribute (if present) is a JavaScript MIME type.  We set
			// inScript provisionally here and correct it when we read attrs.
			switch tagNameLower {
			case "script":
				inScript = true
			case "style":
				inStyle = true
			default:
				if _, ok := rcdataElements[tagNameLower]; ok {
					inRCDATA = true
				}
			}

			// Check if marker is reflected in the tag name itself
			if strings.Contains(strings.ToLower(tagName), markerLower) {
				reflections = append(reflections, ReflectionInfo{
					Context: ContextHTMLText,
					TagName: tagNameLower,
				})
			}

			// Check attributes
			if hasAttr {
				for {
					key, val, moreAttr := tokenizer.TagAttr()
					attrName := strings.ToLower(string(key))
					attrVal := string(val)

					// Fix #2 (cont.): if this is the "type" attribute on a
					// <script> tag and the type is non-executable, demote the
					// script context so text inside is treated as ContextNone.
					if tagNameLower == "script" && attrName == "type" {
						if isNonExecutableScriptType(attrVal) {
							inScript = false
						}
					}

					// Check if marker is in the attribute value
					if strings.Contains(strings.ToLower(attrVal), markerLower) {
						ctx := ContextAttribute

						// Detect quoting style by looking at raw token text
						quote, unquoted := detectAttrQuoting(rawToken, attrName)
						if unquoted {
							ctx = ContextAttributeUnquoted
						}

						if isEventHandler(attrName) {
							// Event handler attributes contain JavaScript
							ctx = ContextScript
						} else if isJavaScriptURI(attrVal) {
							// Fix #1: javascript: URI → treat as script context
							ctx = ContextScript
						} else if attrName == "srcdoc" {
							// Fix #4: srcdoc allows full HTML injection
							ctx = ContextHTMLText
						}

						reflections = append(reflections, ReflectionInfo{
							Context:   ctx,
							AttrName:  attrName,
							QuoteChar: quote,
							TagName:   tagNameLower,
						})
					}

					// Check if marker is in the attribute name
					if strings.Contains(attrName, markerLower) {
						reflections = append(reflections, ReflectionInfo{
							Context: ContextHTMLText,
							TagName: tagNameLower,
						})
					}

					if !moreAttr {
						break
					}
				}
			}

		case html.EndTagToken:
			tn, _ := tokenizer.TagName()
			tagNameLower := strings.ToLower(string(tn))

			switch tagNameLower {
			case "script":
				inScript = false
			case "style":
				inStyle = false
			default:
				if _, ok := rcdataElements[tagNameLower]; ok {
					inRCDATA = false
				}
			}

			// Pop tag stack
			for i := len(tagStack) - 1; i >= 0; i-- {
				if tagStack[i] == tagNameLower {
					tagStack = tagStack[:i]
					break
				}
			}

		case html.TextToken:
			text := string(tokenizer.Text())
			if !strings.Contains(strings.ToLower(text), markerLower) {
				continue
			}

			if inScript {
				ctx := detectScriptStringContext(text, marker)
				parentTag := "script"
				if len(tagStack) > 0 {
					parentTag = tagStack[len(tagStack)-1]
				}
				reflections = append(reflections, ReflectionInfo{
					Context: ctx,
					TagName: parentTag,
				})
			} else if inStyle {
				reflections = append(reflections, ReflectionInfo{
					Context: ContextStyle,
					TagName: "style",
				})
			} else if inRCDATA {
				tag := ""
				if len(tagStack) > 0 {
					tag = tagStack[len(tagStack)-1]
				}
				reflections = append(reflections, ReflectionInfo{
					Context: ContextHTMLText,
					TagName: tag,
				})
			} else {
				tag := ""
				if len(tagStack) > 0 {
					tag = tagStack[len(tagStack)-1]
				}
				reflections = append(reflections, ReflectionInfo{
					Context: ContextHTMLText,
					TagName: tag,
				})
			}

		case html.CommentToken:
			text := string(tokenizer.Text())
			if strings.Contains(strings.ToLower(text), markerLower) {
				reflections = append(reflections, ReflectionInfo{
					Context: ContextHTMLComment,
				})
			}
		}
	}

	return reflections
}

// detectScriptStringContext determines if the marker is inside a JS string literal
// or in bare script code.
func detectScriptStringContext(scriptContent, marker string) Context {
	markerLower := strings.ToLower(marker)
	contentLower := strings.ToLower(scriptContent)

	idx := strings.Index(contentLower, markerLower)
	if idx < 0 {
		return ContextScript
	}

	// Walk through the script content tracking quote state
	inSingleQuote := false
	inDoubleQuote := false
	inBacktick := false
	escaped := false

	for i := 0; i < idx; i++ {
		ch := scriptContent[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		switch ch {
		case '\'':
			if !inDoubleQuote && !inBacktick {
				inSingleQuote = !inSingleQuote
			}
		case '"':
			if !inSingleQuote && !inBacktick {
				inDoubleQuote = !inDoubleQuote
			}
		case '`':
			if !inSingleQuote && !inDoubleQuote {
				inBacktick = !inBacktick
			}
		}
	}

	if inSingleQuote || inDoubleQuote || inBacktick {
		return ContextScriptString
	}
	return ContextScript
}

// detectAttrQuoting detects the quoting style of an attribute from raw HTML.
// Returns the quote character and whether the attribute is unquoted.
func detectAttrQuoting(rawToken, attrName string) (byte, bool) {
	attrAssign := attrName + "="
	rawLower := strings.ToLower(rawToken)
	idx := strings.Index(rawLower, attrAssign)
	if idx < 0 {
		return '"', false // default to double-quoted
	}
	afterEq := idx + len(attrAssign)
	if afterEq >= len(rawToken) {
		return '"', false
	}
	switch rawToken[afterEq] {
	case '"':
		return '"', false
	case '\'':
		return '\'', false
	default:
		return 0, true
	}
}

// BestReflection returns the highest-priority reflection from the list
func BestReflection(reflections []ReflectionInfo) *ReflectionInfo {
	if len(reflections) == 0 {
		return nil
	}

	best := &reflections[0]
	for i := 1; i < len(reflections); i++ {
		if reflections[i].Context.priority() > best.Context.priority() {
			best = &reflections[i]
		}
	}
	return best
}
