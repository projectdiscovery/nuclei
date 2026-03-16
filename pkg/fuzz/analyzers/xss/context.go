package xss

import (
	"strings"

	"golang.org/x/net/html"
)

// DetectReflections parses the HTML body and returns all reflection contexts
// where the marker is found.
func DetectReflections(body string, marker string) []ReflectionInfo {
	// Case-insensitive check for marker reflection
	if !strings.Contains(strings.ToLower(body), strings.ToLower(marker)) {
		return nil
	}

	var reflections []ReflectionInfo
	markerLower := strings.ToLower(marker)

	tokenizer := html.NewTokenizer(strings.NewReader(body))

	var tagStack []string
	inScript := false
	scriptType := "" // Track script type to detect non-executable scripts
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

			switch tagNameLower {
			case "script":
				inScript = true
				scriptType = "" // Reset script type
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

					// Track script type attribute
					if tagNameLower == "script" && attrName == "type" {
						scriptType = strings.ToLower(strings.TrimSpace(attrVal))
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
						}

						// Check for javascript: URI scheme (case-insensitive)
						// Fix for issue #7086 - javascript: URIs should be ContextScript
						if isJavaScriptURI(attrVal) {
							ctx = ContextScript
						}

						// srcdoc attribute allows full HTML injection
						// Fix for issue #7086 - srcdoc should be ContextHTMLText
						if attrName == "srcdoc" {
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

			// For script tags, check if it's a non-executable script type
			// Fix for issue #7086 - Non-executable script types should not be treated as executable
			if tagNameLower == "script" && !isExecutableScriptType(scriptType) {
				inScript = false // Don't treat as executable script context
			}

		case html.EndTagToken:
			tn, _ := tokenizer.TagName()
			tagNameLower := strings.ToLower(string(tn))

			switch tagNameLower {
			case "script":
				inScript = false
				scriptType = ""
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

// isJavaScriptURI checks if the attribute value is a javascript: URI scheme
// Handles case-insensitive matching and leading whitespace per URL spec
// Fix for issue #7086 - javascript: URIs should be classified as ContextScript
func isJavaScriptURI(value string) bool {
	// Strip leading whitespace and C0 control characters (per URL spec)
	trimmed := strings.TrimLeftFunc(value, func(r rune) bool {
		return r <= 0x20 // C0 control chars and space
	})

	// Case-insensitive check for "javascript:"
	prefix := "javascript:"
	if len(trimmed) < len(prefix) {
		return false
	}
	return strings.EqualFold(trimmed[:len(prefix)], prefix)
}

// isExecutableScriptType checks if a script type attribute indicates executable JavaScript
// Non-executable types include application/json, application/ld+json, importmap, etc.
// Fix for issue #7086 - Non-executable script types should not be treated as executable
func isExecutableScriptType(scriptType string) bool {
	if scriptType == "" {
		return true // Empty type defaults to JavaScript
	}

	// List of known JavaScript MIME types (WHATWG spec)
	// https://html.spec.whatwg.org/multipage/scripting.html#javascript-mime-type
	// Using word-boundary matching to avoid data-type= false positives
	jsTypes := map[string]struct{}{
		"application/ecmascript":          {},
		"application/javascript":          {},
		"application/x-ecmascript":        {},
		"application/x-javascript":        {},
		"text/ecmascript":                 {},
		"text/javascript":                 {},
		"text/javascript1.0":              {},
		"text/javascript1.1":              {},
		"text/javascript1.2":              {},
		"text/javascript1.3":              {},
		"text/javascript1.4":              {},
		"text/javascript1.5":              {},
		"text/jscript":                    {},
		"text/livescript":                 {},
		"text/x-ecmascript":               {},
		"text/x-javascript":               {},
		"module":                          {},
	}

	_, isJS := jsTypes[scriptType]
	return isJS
}

// BestReflection returns the highest-priority reflection from the list
func BestReflection(reflections []ReflectionInfo) *ReflectionInfo {
	if len(reflections) == 0 {
		return nil
	}

	best := &reflections[0]
	for i := 1; i < len(reflections); i++ {
		// Skip ContextNone reflections
		if reflections[i].Context == ContextNone {
			continue
		}
		if best.Context == ContextNone || reflections[i].Context.priority() > best.Context.priority() {
			best = &reflections[i]
		}
	}

	// Return nil if best is ContextNone
	if best.Context == ContextNone {
		return nil
	}
	return best
}
