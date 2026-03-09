package xss

import (
	"strings"

	"golang.org/x/net/html"
)

// DetectReflections parses the HTML body and returns all reflection contexts
// where the marker is found.
func DetectReflections(body string, marker string) []ReflectionInfo {
	// Use case-insensitive check to avoid short-circuiting on mixed-case reflections
	markerLower := strings.ToLower(marker)
	bodyLower := strings.ToLower(body)
	if !strings.Contains(bodyLower, markerLower) {
		return nil
	}

	var reflections []ReflectionInfo

	tokenizer := html.NewTokenizer(strings.NewReader(body))

	var tagStack []string
	inScript := false
	inStyle := false
	inRCDATA := false
	scriptType := "" // Track script type to handle application/json

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

			// Check if marker is reflected in the tag name itself
			if strings.Contains(strings.ToLower(tagName), markerLower) {
				reflections = append(reflections, ReflectionInfo{
					Context: ContextHTMLText,
					TagName: tagNameLower,
				})
			}

			// Check for script type attribute and collect all attributes for marker checking
			isScriptTag := tagNameLower == "script"
			currentScriptType := ""
			
			// FIX #1: Collect ALL attributes first before checking any of them for the marker.
			// tokenizer.TagAttr() advances an internal cursor and does not reset, so we cannot
			// have separate loops for type checking and marker checking - all attributes must
			// be collected in a single pass, then checked in a separate loop.
			type attrInfo struct {
				name  string
				value string
				raw   string
			}
			var attrs []attrInfo
			
			if hasAttr {
				for {
					key, val, moreAttr := tokenizer.TagAttr()
					attrName := strings.ToLower(string(key))
					attrVal := string(val)
					attrs = append(attrs, attrInfo{name: attrName, value: attrVal, raw: rawToken})
					
					// Check for type attribute on script tags
					if isScriptTag && attrName == "type" {
						currentScriptType = strings.ToLower(attrVal)
					}
					
					if !moreAttr {
						break
					}
				}
			}

			switch tagNameLower {
			case "script":
				// FIX #2: Only treat actual JavaScript MIME types as executable script
				// Non-JavaScript types (JSON, JSON-LD, etc.) are treated as data blocks
				inScript = isJavaScriptMIMEType(currentScriptType)
				if !inScript {
					scriptType = currentScriptType
				} else {
					scriptType = ""
				}
			case "style":
				inStyle = true
			default:
				if _, ok := rcdataElements[tagNameLower]; ok {
					inRCDATA = true
				}
			}

			// Check all collected attributes for marker
			for _, attr := range attrs {
				attrName := attr.name
				attrVal := attr.value

				// Check if marker is in the attribute value
				if strings.Contains(strings.ToLower(attrVal), markerLower) {
					ctx := ContextAttribute

					// Detect quoting style by looking at raw token text
					quote, unquoted := detectAttrQuoting(attr.raw, attrName)
					if unquoted {
						ctx = ContextAttributeUnquoted
					}

					// FIX #1 & #3: javascript: URIs should be treated as executable script context
					// Only for executable URL sinks in appropriate tag contexts
					// Inert attributes like title, data-x should remain as ContextHTMLText
					if isJavaScriptURI(attrVal) && isExecutableURLSink(tagNameLower, attrName) {
						ctx = ContextScript
					}

					// FIX #4: srcdoc should be treated as HTML injection context
					if attrName == "srcdoc" {
						ctx = ContextHTMLText
					}

					if isEventHandler(attrName) {
						// Event handler attributes contain JavaScript
						ctx = ContextScript
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
// FIX #4: Now handles optional whitespace around = (e.g., href = "value" or href= value)
func detectAttrQuoting(rawToken, attrName string) (byte, bool) {
	attrNameLower := strings.ToLower(attrName)
	rawLower := strings.ToLower(rawToken)
	
	// Find the attribute name in the raw token
	idx := strings.Index(rawLower, attrNameLower)
	if idx < 0 {
		return '"', false // default to double-quoted
	}
	
	// Look for = after the attribute name, skipping whitespace
	pos := idx + len(attrNameLower)
	for pos < len(rawToken) && (rawToken[pos] == ' ' || rawToken[pos] == '\t' || rawToken[pos] == '\n' || rawToken[pos] == '\r') {
		pos++
	}
	
	// Check if we found =
	if pos >= len(rawToken) || rawToken[pos] != '=' {
		return '"', false // default to double-quoted
	}
	pos++ // skip the =
	
	// Skip whitespace after =
	for pos < len(rawToken) && (rawToken[pos] == ' ' || rawToken[pos] == '\t' || rawToken[pos] == '\n' || rawToken[pos] == '\r') {
		pos++
	}
	
	if pos >= len(rawToken) {
		return '"', false
	}
	
	switch rawToken[pos] {
	case '"':
		return '"', false
	case '\'':
		return '\'', false
	default:
		return 0, true
	}
}

// isExecutableURLSink checks if a tag+attribute pair is an executable URL sink
// that can execute JavaScript when containing javascript: URIs
// FIX #3: Now considers both tag and attribute context, not just attribute name
// Inert attributes like title, data-*, alt, etc. should NOT be in this list
func isExecutableURLSink(tagName, attrName string) bool {
	tagLower := strings.ToLower(tagName)
	attrLower := strings.ToLower(attrName)
	
	// Check tag-specific executable sinks
	switch tagLower {
	case "a", "area":
		return attrLower == "href"
	case "form":
		return attrLower == "action"
	case "button", "input":
		return attrLower == "formaction"
	case "iframe", "script", "img", "audio", "video", "embed", "object", "source", "track":
		return attrLower == "src"
	case "object", "embed":
		return attrLower == "data"
	case "img", "video":
		return attrLower == "poster"
	case "img", "source":
		return attrLower == "srcset"
	case "link":
		return attrLower == "href" || attrLower == "xlink:href"
	case "base":
		return attrLower == "href"
	default:
		return false
	}
}

// isJavaScriptURI checks if an attribute value is a javascript: URI
// FIX #1: These should be treated as executable script context
func isJavaScriptURI(attrVal string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(attrVal))
	return strings.HasPrefix(trimmed, "javascript:")
}

// isJavaScriptMIMEType checks if a script type attribute is a JavaScript MIME type
// FIX #2: Only actual JavaScript MIME types should be treated as executable
// Non-JavaScript types like application/json, application/ld+json, text/vbscript, etc. are data blocks
func isJavaScriptMIMEType(mimeType string) bool {
	if mimeType == "" {
		// No type attribute defaults to JavaScript (executable)
		return true
	}
	mimeTypeLower := strings.ToLower(mimeType)
	// JavaScript MIME types (executable)
	switch mimeTypeLower {
	case "text/javascript", "application/javascript", "application/x-javascript", "text/ecmascript", "application/ecmascript":
		return true
	default:
		// All other types (application/json, application/ld+json, text/vbscript, etc.) are non-executable
		return false
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
