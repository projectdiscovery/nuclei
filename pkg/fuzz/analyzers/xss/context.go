package xss

import (
	"strings"

	"golang.org/x/net/html"
)

// DetectReflections parses the HTML body and returns all reflection contexts
// where the marker is found.
func DetectReflections(body string, marker string) []ReflectionInfo {
	// Fix #3: Make reflection detection case-insensitive
	if !strings.Contains(strings.ToLower(body), strings.ToLower(marker)) {
		return nil
	}

	var reflections []ReflectionInfo
	markerLower := strings.ToLower(marker)

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

			switch tagNameLower {
			case "script":
				// Fix #2: Check if this is a JSON script block (non-executable)
				isJSONScript := false
				if hasAttr {
					isJSONScript = isNonExecutableScript(rawToken)
				}
				if !isJSONScript {
					inScript = true
				}
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
						} else if attrName == "srcdoc" {
							// Fix #4: srcdoc attributes allow full HTML injection
							ctx = ContextHTMLText
						} else if attrName == "href" || attrName == "src" {
							// Fix #1: javascript: URIs should be classified as ContextScript
							if isJavaScriptURI(attrVal) {
								ctx = ContextScript
							}
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

// isJavaScriptURI checks if a URI value uses the javascript: protocol
func isJavaScriptURI(uri string) bool {
	// Trim leading/trailing whitespace
	uri = strings.TrimSpace(uri)
	// Case-insensitive check for javascript: prefix
	return strings.HasPrefix(strings.ToLower(uri), "javascript:")
}

// isNonExecutableScript checks if a script tag has a non-executable type attribute
// (e.g., application/json, application/ld+json)
func isNonExecutableScript(rawToken string) bool {
	rawLower := strings.ToLower(rawToken)
	// Look for type= attribute
	typeIdx := strings.Index(rawLower, "type=")
	if typeIdx < 0 {
		return false
	}
	
	// Extract the type value
	afterEq := typeIdx + 5
	if afterEq >= len(rawToken) {
		return false
	}
	
	// Find the value (accounting for quotes)
	var typeValue string
	if rawToken[afterEq] == '"' || rawToken[afterEq] == '\'' {
		quote := rawToken[afterEq]
		endQuote := strings.IndexByte(rawToken[afterEq+1:], quote)
		if endQuote >= 0 {
			typeValue = strings.ToLower(rawToken[afterEq+1 : afterEq+1+endQuote])
		}
	} else {
		// Unquoted value - read until whitespace or >
		end := afterEq
		for end < len(rawToken) && rawToken[end] != ' ' && rawToken[end] != '\t' && rawToken[end] != '\n' && rawToken[end] != '\r' && rawToken[end] != '>' {
			end++
		}
		typeValue = strings.ToLower(rawToken[afterEq:end])
	}
	
	// Check if it's a non-executable type
	nonExecutableTypes := []string{
		"application/json",
		"application/ld+json",
		"text/json",
		"importmap",
	}
	
	for _, nonExec := range nonExecutableTypes {
		if typeValue == nonExec {
			return true
		}
	}
	
	return false
}
