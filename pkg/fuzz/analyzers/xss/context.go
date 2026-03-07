package xss

import (
	"strings"

	"golang.org/x/net/html"
)

// DetectReflections parses the HTML body and returns all reflection contexts
// where the marker is found.
func DetectReflections(body string, marker string) []ReflectionInfo {
	if !strings.Contains(body, marker) {
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

					// Check if marker is in the attribute value
					if strings.Contains(strings.ToLower(attrVal), markerLower) {
						ctx := ContextAttribute

						// Detect quoting style by looking at raw token text.
						// If we can't resolve it precisely, keep analyzer behavior conservative
						// by defaulting to double-quoted attribute handling at the call site.
						quote, unquoted := detectAttrQuoting(rawToken, attrName)
						if unquoted {
							ctx = ContextAttributeUnquoted
						} else if quote == 0 {
							quote = '"'
						}

						// Check for javascript: URI in URL-context attributes - treat as script context
						if attrName == "href" || attrName == "src" || attrName == "action" || attrName == "formaction" || attrName == "data" || attrName == "cite" || attrName == "poster" {
							if strings.HasPrefix(strings.ToLower(strings.TrimSpace(attrVal)), "javascript:") {
								ctx = ContextScript
							}
						}

						// Check for srcdoc attribute - allows HTML injection
						if attrName == "srcdoc" {
							ctx = ContextHTMLText
						}

						// Event handler attributes contain JavaScript
						if isEventHandler(attrName) {
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

	// Walk through the script content tracking quote state.
	// For template literals, track ${...} expression blocks separately, because
	// marker inside ${...} is JS expression context, not string-literal context.
	inSingleQuote := false
	inDoubleQuote := false
	inBacktick := false
	inTemplateExpr := false
	templateExprDepth := 0
	escaped := false

	for i := 0; i < idx; i++ {
		ch := scriptContent[i]

		if escaped {
			escaped = false
			continue
		}

		if inSingleQuote {
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '\'' {
				inSingleQuote = false
			}
			continue
		}

		if inDoubleQuote {
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				inDoubleQuote = false
			}
			continue
		}

		if inBacktick {
			if inTemplateExpr {
				switch ch {
				case '{':
					templateExprDepth++
				case '}':
					templateExprDepth--
					if templateExprDepth == 0 {
						inTemplateExpr = false
					}
				case '\'':
					inSingleQuote = true
				case '"':
					inDoubleQuote = true
				case '`':
					inBacktick = true
				}
				continue
			}

			if ch == '\\' {
				escaped = true
				continue
			}

			if ch == '$' && i+1 < idx && scriptContent[i+1] == '{' {
				inTemplateExpr = true
				templateExprDepth = 1
				i++
				continue
			}

			if ch == '`' {
				inBacktick = false
			}
			continue
		}

		switch ch {
		case '\'':
			inSingleQuote = true
		case '"':
			inDoubleQuote = true
		case '`':
			inBacktick = true
		}
	}

	if inSingleQuote || inDoubleQuote || (inBacktick && !inTemplateExpr) {
		return ContextScriptString
	}
	return ContextScript
}

// detectAttrQuoting detects the quoting style of an attribute from raw HTML.
// Returns the quote character and whether the attribute is unquoted.
// If the exact attribute assignment cannot be resolved, it returns (0, false).
func detectAttrQuoting(rawToken, attrName string) (byte, bool) {
	rawLower := strings.ToLower(rawToken)
	attrLower := strings.ToLower(attrName)

	searchFrom := 0
	for {
		rel := strings.Index(rawLower[searchFrom:], attrLower)
		if rel < 0 {
			return 0, false
		}
		idx := searchFrom + rel

		// Ensure we matched a full attribute name boundary (not a suffix/prefix of another token)
		if idx > 0 {
			prev := rawLower[idx-1]
			if isAttrNameChar(prev) {
				searchFrom = idx + len(attrLower)
				continue
			}
		}
		afterName := idx + len(attrLower)
		if afterName < len(rawLower) {
			next := rawLower[afterName]
			if isAttrNameChar(next) {
				searchFrom = idx + len(attrLower)
				continue
			}
		}

		pos := afterName
		for pos < len(rawToken) && isHTMLSpace(rawToken[pos]) {
			pos++
		}
		if pos >= len(rawToken) || rawToken[pos] != '=' {
			searchFrom = idx + len(attrLower)
			continue
		}
		pos++
		for pos < len(rawToken) && isHTMLSpace(rawToken[pos]) {
			pos++
		}
		if pos >= len(rawToken) {
			return 0, false
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
}

func isAttrNameChar(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == ':'
}

func isHTMLSpace(ch byte) bool {
	switch ch {
	case ' ', '\t', '\n', '\r', '\f':
		return true
	default:
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
