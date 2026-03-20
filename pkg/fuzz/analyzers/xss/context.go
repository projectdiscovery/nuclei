package xss

import (
	"strings"

	"golang.org/x/net/html"
)

// DetectReflections parses the HTML body and returns all reflection contexts
// where the marker is found.
func DetectReflections(body string, marker string) []ReflectionInfo {
	bodyLower := strings.ToLower(body)
	markerLower := strings.ToLower(marker)

	// [FIX 3] Case-insensitive early exit — if the marker doesn't appear
	// in any case form, skip tokenization entirely.
	if !strings.Contains(bodyLower, markerLower) {
		return nil
	}

	var reflections []ReflectionInfo

	tokenizer := html.NewTokenizer(strings.NewReader(body))

	var tagStack []string
	inScript := false
	inStyle := false
	inRCDATA := false
	// [FIX 2] Track the current <script> tag's type attribute so we can
	// distinguish executable scripts from data blocks like application/json.
	currentScriptType := ""

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

			// Collect all attributes first so we can inspect the type attr
			// on <script> tags before deciding context.
			type attrPair struct {
				name, val string
			}
			var attrs []attrPair
			scriptTypeVal := ""

			if hasAttr {
				for {
					key, val, moreAttr := tokenizer.TagAttr()
					aName := strings.ToLower(string(key))
					aVal := string(val)
					attrs = append(attrs, attrPair{aName, aVal})
					if aName == "type" && tagNameLower == "script" {
						scriptTypeVal = aVal
					}
					if !moreAttr {
						break
					}
				}
			}

			switch tagNameLower {
			case "script":
				inScript = true
				currentScriptType = scriptTypeVal
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

			// Check attributes for marker reflection
			for _, attr := range attrs {
				// Check if marker is in the attribute value
				if strings.Contains(strings.ToLower(attr.val), markerLower) {
					ctx := ContextAttribute

					// Detect quoting style by looking at raw token text
					quote, unquoted := detectAttrQuoting(rawToken, attr.name)
					if unquoted {
						ctx = ContextAttributeUnquoted
					}

					// [FIX 4] srcdoc attributes contain full HTML — classify as
					// HTML text context since the browser parses the value as a
					// complete HTML document.
					if isSrcdocAttr(attr.name) {
						ctx = ContextHTMLText
					} else if isEventHandler(attr.name) {
						// Event handler attributes contain JavaScript
						ctx = ContextScript
					} else if _, isSink := javascriptURIAttrs[attr.name]; isSink && isJavascriptURI(attr.val) {
						// [FIX 1] javascript: URIs in navigable attributes (href, src,
						// action, etc.) are executable — classify as script context.
						ctx = ContextScript
					}

					reflections = append(reflections, ReflectionInfo{
						Context:   ctx,
						AttrName:  attr.name,
						QuoteChar: quote,
						TagName:   tagNameLower,
					})
				}

				// Check if marker is in the attribute name
				if strings.Contains(attr.name, markerLower) {
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
				currentScriptType = ""
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
				// [FIX 2] Non-executable script blocks (e.g. application/json,
				// application/ld+json) are data — a </script> breakout is possible
				// but the content itself isn't executed by the JS engine.
				if !isExecutableScriptType(currentScriptType) {
					parentTag := "script"
					if len(tagStack) > 0 {
						parentTag = tagStack[len(tagStack)-1]
					}
					reflections = append(reflections, ReflectionInfo{
						Context: ContextScriptData,
						TagName: parentTag,
					})
				} else {
					ctx := detectScriptStringContext(text, marker)
					parentTag := "script"
					if len(tagStack) > 0 {
						parentTag = tagStack[len(tagStack)-1]
					}
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
// Handles whitespace around the '=' sign (e.g. attr = "value").
func detectAttrQuoting(rawToken, attrName string) (byte, bool) {
	rawLower := strings.ToLower(rawToken)
	attrIdx := strings.Index(rawLower, attrName)
	if attrIdx < 0 {
		return '"', false // default to double-quoted
	}

	// Find the '=' after the attribute name, skipping whitespace
	eqIdx := -1
	for i := attrIdx + len(attrName); i < len(rawLower); i++ {
		if rawLower[i] == '=' {
			eqIdx = i
			break
		}
		if rawLower[i] != ' ' && rawLower[i] != '\t' && rawLower[i] != '\n' && rawLower[i] != '\r' {
			break
		}
	}
	if eqIdx < 0 {
		return '"', false
	}

	// Skip whitespace after '='
	afterEq := eqIdx + 1
	for afterEq < len(rawToken) && (rawToken[afterEq] == ' ' || rawToken[afterEq] == '\t' ||
		rawToken[afterEq] == '\n' || rawToken[afterEq] == '\r') {
		afterEq++
	}
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
// Reflections with ContextNone are skipped.
func BestReflection(reflections []ReflectionInfo) *ReflectionInfo {
	if len(reflections) == 0 {
		return nil
	}

	var best *ReflectionInfo
	for i := range reflections {
		if reflections[i].Context == ContextNone {
			continue
		}
		if best == nil || reflections[i].Context.priority() > best.Context.priority() {
			best = &reflections[i]
		}
	}
	return best
}
