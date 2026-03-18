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

			if tagNameLower == "style" {
				inStyle = true
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

						if isScriptURLAttribute(attrName) {
							normalizedVal := normalizeURIScheme(attrVal)
							if strings.HasPrefix(normalizedVal, "javascript:") || strings.HasPrefix(normalizedVal, "vbscript:") {
								ctx = ContextScript
							} else if strings.HasPrefix(normalizedVal, "data:") {
								// Parse media-type only (before , or ;) to avoid false positives on payload data
								dataRest := strings.TrimPrefix(normalizedVal, "data:")
								mediaType := strings.ToLower(strings.TrimSpace(
									strings.SplitN(strings.SplitN(dataRest, ",", 2)[0], ";", 2)[0]))
								if mediaType == "text/html" || mediaType == "image/svg+xml" || mediaType == "application/xhtml+xml" {
									ctx = ContextScript
								}
							}
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
			} else {
				// Both RCDATA and regular text are HTML text contexts.
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
	if normalized == "" {
		return true
	}
	// Extract MIME essence by stripping parameters after ';'.
	// Per WHATWG spec, "text/javascript; charset=utf-8" has essence "text/javascript" → executable.
	if idx := strings.IndexByte(normalized, ';'); idx >= 0 {
		normalized = strings.TrimSpace(normalized[:idx])
		if normalized == "" {
			return false // e.g. ";charset=utf-8" — invalid MIME type, not executable
		}
	}

	switch normalized {
	case "text/javascript", "text/ecmascript",
		"text/javascript1.0", "text/javascript1.1", "text/javascript1.2",
		"text/javascript1.3", "text/javascript1.4", "text/javascript1.5",
		"text/jscript", "text/livescript",
		"text/x-ecmascript", "text/x-javascript",
		"application/javascript", "application/ecmascript",
		"application/x-ecmascript", "application/x-javascript",
		"module":
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
	// Handle optional whitespace around = (e.g. href = "val")
	rawLower := strings.ToLower(rawToken)
	attrLower := strings.ToLower(attrName)
	searchStart := 0
	idx := -1
	eqOffset := 0
	for {
		pos := strings.Index(rawLower[searchStart:], attrLower)
		if pos < 0 {
			break
		}
		absPos := searchStart + pos
		if absPos == 0 || isAttrBoundary(rawLower[absPos-1]) {
			// skip optional whitespace after attr name, then require =
			i := absPos + len(attrLower)
			for i < len(rawLower) && (rawLower[i] == ' ' || rawLower[i] == '\t') {
				i++
			}
			if i < len(rawLower) && rawLower[i] == '=' {
				idx = absPos
				eqOffset = i - absPos
				break
			}
		}
		searchStart = absPos + 1
	}
	if idx < 0 {
		return '"', false // default to double-quoted
	}
	afterEq := idx + eqOffset + 1
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

func isAttrBoundary(ch byte) bool {
	switch ch {
	case ' ', '\t', '\n', '\r', '/':
		return true
	default:
		return false
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
