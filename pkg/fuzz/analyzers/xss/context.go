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
			case "script":
				scriptType := extractAttrFromRaw(rawToken, "type")
				if isExecutableScriptType(scriptType) {
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
						} else if isJavascriptURI(attrVal) && isURLAttribute(attrName) {
							ctx = ContextScript
						} else if attrName == "srcdoc" {
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

// extractAttrFromRaw extracts an attribute value from raw HTML token text.
// It supports optional whitespace around "=" and avoids partial matches such as
// matching "value" inside "data-value".
func extractAttrFromRaw(rawToken, attrName string) string {
	valueStart, ok := findAttrValueStart(rawToken, attrName)
	if !ok || valueStart >= len(rawToken) {
		return ""
	}
	rest := rawToken[valueStart:]
	if len(rest) == 0 {
		return ""
	}
	if rest[0] == '"' || rest[0] == '\'' {
		quote := rest[0]
		end := strings.IndexByte(rest[1:], quote)
		if end < 0 {
			return rest[1:]
		}
		return rest[1 : end+1]
	}
	end := strings.IndexAny(rest, " \t\n\r>")
	if end < 0 {
		return rest
	}
	return rest[:end]
}

func findAttrValueStart(rawToken, attrName string) (int, bool) {
	rawLower := strings.ToLower(rawToken)
	attrLower := strings.ToLower(attrName)
	searchFrom := 0

	for searchFrom < len(rawLower) {
		relIdx := strings.Index(rawLower[searchFrom:], attrLower)
		if relIdx < 0 {
			return 0, false
		}

		idx := searchFrom + relIdx
		if idx > 0 {
			prev := rawLower[idx-1]
			if !isAttrBoundary(prev) {
				searchFrom = idx + 1
				continue
			}
		}

		pos := idx + len(attrLower)
		if pos >= len(rawLower) {
			return 0, false
		}
		if !isHTMLSpace(rawLower[pos]) && rawLower[pos] != '=' {
			searchFrom = idx + 1
			continue
		}

		for pos < len(rawLower) && isHTMLSpace(rawLower[pos]) {
			pos++
		}
		if pos >= len(rawLower) || rawLower[pos] != '=' {
			searchFrom = idx + 1
			continue
		}
		pos++
		for pos < len(rawLower) && isHTMLSpace(rawLower[pos]) {
			pos++
		}

		return pos, true
	}

	return 0, false
}

func isHTMLSpace(ch byte) bool {
	switch ch {
	case ' ', '\t', '\n', '\r', '\f':
		return true
	default:
		return false
	}
}

func isAttrBoundary(ch byte) bool {
	return ch == '<' || isHTMLSpace(ch)
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
// It supports optional whitespace around "=" and skips partial suffix matches.
// Returns the quote character and whether the attribute is unquoted.
func detectAttrQuoting(rawToken, attrName string) (byte, bool) {
	valueStart, ok := findAttrValueStart(rawToken, attrName)
	if !ok || valueStart >= len(rawToken) {
		return '"', false // default to double-quoted
	}
	switch rawToken[valueStart] {
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
