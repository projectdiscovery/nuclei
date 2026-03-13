package xss

import (
	"strings"

	"golang.org/x/net/html"
)

// DetectReflections parses the HTML body and returns all reflection contexts
// where the marker is found.
func DetectReflections(body string, marker string) []ReflectionInfo {
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

			hasScriptType := false
			scriptType := ""

			// Check attributes
			if hasAttr {
				for {
					key, val, moreAttr := tokenizer.TagAttr()
					attrName := strings.ToLower(string(key))
					attrVal := string(val)

					if tagNameLower == "script" && attrName == "type" {
						hasScriptType = true
						scriptType = attrVal
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

						if strings.HasPrefix(strings.ToLower(strings.TrimSpace(attrVal)), "javascript:") {
							ctx = ContextScript
						}

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

			if tt == html.StartTagToken && tagNameLower == "script" {
				inScript = isExecutableScriptType(hasScriptType, scriptType)
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

// isExecutableScriptType returns true if the script type attribute indicates
// executable JavaScript. Scripts without a type attribute are executable by default.
func isExecutableScriptType(hasType bool, scriptType string) bool {
	if !hasType {
		return true
	}

	normalized := strings.ToLower(strings.TrimSpace(scriptType))
	if idx := strings.Index(normalized, ";"); idx >= 0 {
		normalized = strings.TrimSpace(normalized[:idx])
	}

	if normalized == "" {
		return true
	}

	switch normalized {
	case "text/javascript", "text/ecmascript", "application/javascript", "application/ecmascript", "module":
		return true
	default:
		return false
	}
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

// BestReflection returns the highest-priority reflection from the list.
// Returns a copy so the caller is not aliased to the original slice.
func BestReflection(reflections []ReflectionInfo) *ReflectionInfo {
	if len(reflections) == 0 {
		return nil
	}

	bestIdx := 0
	for i := 1; i < len(reflections); i++ {
		if reflections[i].Context.priority() > reflections[bestIdx].Context.priority() {
			bestIdx = i
		}
	}
	result := reflections[bestIdx]
	return &result
}
