package xss

import (
	"strings"

	"golang.org/x/net/html"
)

// DetectReflections parses the HTML body and returns all reflection contexts
// where the marker is found.
func DetectReflections(body string, marker string) []ReflectionInfo {
	// Case-insensitive check for marker presence (fixes issue #7086 point 3)
	if !strings.Contains(strings.ToLower(body), strings.ToLower(marker)) {
		return nil
	}

	var reflections []ReflectionInfo
	markerLower := strings.ToLower(marker)

	tokenizer := html.NewTokenizer(strings.NewReader(body))

	var tagStack []string
	inScript := false
	inExecutableScript := false // true if script is executable (not JSON/template)
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
				// Check script type attribute to determine if executable (fixes issue #7086 point 2)
				inExecutableScript = isExecutableScript(rawToken)
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
						} else if isJavaScriptURI(attrName, attrVal) {
							// javascript: URIs in href/src/etc are executable (fixes issue #7086 point 1)
							ctx = ContextScript
						} else if isSrcdocAttr(attrName) {
							// srcdoc allows full HTML injection (fixes issue #7086 point 4)
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
				inExecutableScript = false
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
				parentTag := "script"
				if len(tagStack) > 0 {
					parentTag = tagStack[len(tagStack)-1]
				}
				// Non-executable scripts (JSON, templates) are not XSS contexts (fixes issue #7086 point 2)
				if !inExecutableScript {
					reflections = append(reflections, ReflectionInfo{
						Context: ContextNone,
						TagName: parentTag,
					})
				} else {
					ctx := detectScriptStringContext(text, marker)
					reflections = append(reflections, ReflectionInfo{
						Context: ctx,
						TagName: parentTag,
					})
				}
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

// javascriptURIAttrs are attributes that can contain javascript: URIs
var javascriptURIAttrs = map[string]struct{}{
	"href":       {},
	"src":        {},
	"action":     {},
	"formaction": {},
	"xlink:href": {},
	"data":       {},
	"poster":     {},
}

// isJavaScriptURI returns true if the attribute contains a javascript: URI
func isJavaScriptURI(attrName, attrVal string) bool {
	if _, ok := javascriptURIAttrs[attrName]; !ok {
		return false
	}
	// Trim whitespace and check for javascript: protocol (case-insensitive)
	trimmed := strings.TrimSpace(attrVal)
	return strings.HasPrefix(strings.ToLower(trimmed), "javascript:")
}

// isSrcdocAttr returns true if the attribute is srcdoc (allows HTML injection)
func isSrcdocAttr(attrName string) bool {
	return attrName == "srcdoc"
}

// nonExecutableScriptTypes are MIME types that are not JavaScript-executable
var nonExecutableScriptTypes = map[string]struct{}{
	"application/json":          {},
	"application/ld+json":       {},
	"application/json+ld":       {},
	"text/template":             {},
	"text/x-template":           {},
	"text/html":                 {},
	"text/x-handlebars-template": {},
	"text/x-mustache-template":  {},
}

// isExecutableScript checks if a script tag is executable JavaScript
// by examining its type attribute. Returns true if executable.
func isExecutableScript(rawToken string) bool {
	rawLower := strings.ToLower(rawToken)
	
	// Look for type attribute
	typeIdx := strings.Index(rawLower, "type=")
	if typeIdx < 0 {
		// No type attribute means default JavaScript (executable)
		return true
	}
	
	// Extract the type value
	afterEq := typeIdx + len("type=")
	if afterEq >= len(rawToken) {
		return true
	}
	
	var typeVal string
	switch rawToken[afterEq] {
	case '"':
		endIdx := strings.Index(rawToken[afterEq+1:], "\"")
		if endIdx >= 0 {
			typeVal = rawToken[afterEq+1 : afterEq+1+endIdx]
		}
	case '\'':
		endIdx := strings.Index(rawToken[afterEq+1:], "'")
		if endIdx >= 0 {
			typeVal = rawToken[afterEq+1 : afterEq+1+endIdx]
		}
	default:
		// Unquoted - take until space or >
		rest := rawToken[afterEq:]
		endIdx := strings.IndexAny(rest, " \t\n\r>")
		if endIdx >= 0 {
			typeVal = rest[:endIdx]
		} else {
			typeVal = rest
		}
	}
	
	typeVal = strings.TrimSpace(strings.ToLower(typeVal))
	
	// Check if it's a non-executable type
	if _, ok := nonExecutableScriptTypes[typeVal]; ok {
		return false
	}
	
	// Also check for module (executable) vs importmap (not executable)
	if typeVal == "importmap" || typeVal == "speculationrules" {
		return false
	}
	
	return true
}
