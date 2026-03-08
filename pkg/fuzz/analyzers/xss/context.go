package xss

import (
	"strings"

	"golang.org/x/net/html"
)

// DetectReflections parses the HTML body and returns all reflection contexts
// where the marker is found. All comparisons are case-insensitive so
// server-side casing transformations do not cause missed reflections.
func DetectReflections(body string, marker string) []ReflectionInfo {
	markerLower := strings.ToLower(marker)
	bodyLower := strings.ToLower(body)

	if !strings.Contains(bodyLower, markerLower) {
		return nil
	}

	var reflections []ReflectionInfo

	tokenizer := html.NewTokenizer(strings.NewReader(body))

	var tagStack []string
	inScript := false
	executableScript := false
	inStyle := false
	inRCDATA := false

	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}

		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
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
				executableScript = isExecutableScriptTag(rawToken)
			case "style":
				inStyle = true
			default:
				if _, ok := rcdataElements[tagNameLower]; ok {
					inRCDATA = true
				}
			}

			if strings.Contains(strings.ToLower(tagName), markerLower) {
				reflections = append(reflections, ReflectionInfo{
					Context: ContextHTMLText,
					TagName: tagNameLower,
				})
			}

			if hasAttr {
				for {
					key, val, moreAttr := tokenizer.TagAttr()
					attrName := strings.ToLower(string(key))
					attrVal := string(val)

					if strings.Contains(strings.ToLower(attrVal), markerLower) {
						ctx := ContextAttribute

						quote, unquoted := detectAttrQuoting(rawToken, attrName)
						if unquoted {
							ctx = ContextAttributeUnquoted
						}

						if isEventHandler(attrName) {
							ctx = ContextScript
						} else if isJavascriptURI(attrVal) {
							ctx = ContextScript
						} else if isDataExecutableURI(attrVal) {
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
				executableScript = false
			case "style":
				inStyle = false
			default:
				if _, ok := rcdataElements[tagNameLower]; ok {
					inRCDATA = false
				}
			}

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

			if inScript && executableScript {
				ctx := detectScriptStringContext(text, marker)
				parentTag := "script"
				if len(tagStack) > 0 {
					parentTag = tagStack[len(tagStack)-1]
				}
				reflections = append(reflections, ReflectionInfo{
					Context: ctx,
					TagName: parentTag,
				})
			} else if inScript {
				reflections = append(reflections, ReflectionInfo{
					Context: ContextNone,
					TagName: "script",
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

// isJavascriptURI reports whether attrVal is a javascript: URI.
// Browsers strip ASCII control characters (0x00-0x1F) and whitespace before
// parsing the scheme, so "\tjavascript:alert()" is executable.
// Ref: https://url.spec.whatwg.org/#url-parsing (step 1: strip leading C0+space)
func isJavascriptURI(attrVal string) bool {
	stripped := stripLeadingControlAndSpace(attrVal)
	return strings.HasPrefix(strings.ToLower(stripped), "javascript:")
}

// isDataExecutableURI detects data: URIs that produce executable contexts:
//   - data:text/html,... allows full HTML+JS injection
//   - data:text/javascript,... / data:application/javascript,... are direct JS
//   - data:image/svg+xml,... can contain embedded <script> in SVG
func isDataExecutableURI(attrVal string) bool {
	stripped := stripLeadingControlAndSpace(attrVal)
	lower := strings.ToLower(stripped)
	if !strings.HasPrefix(lower, "data:") {
		return false
	}
	rest := lower[5:]
	// Extract MIME type (everything before the first comma, semicolon, or end)
	end := strings.IndexAny(rest, ",;")
	if end < 0 {
		return false
	}
	mime := strings.TrimSpace(rest[:end])
	switch mime {
	case "text/html", "text/javascript", "application/javascript", "application/xhtml+xml", "image/svg+xml":
		return true
	}
	return false
}

// stripLeadingControlAndSpace removes leading ASCII C0 control characters
// (0x00-0x1F) and spaces, matching browser URL parsing behavior.
func stripLeadingControlAndSpace(s string) string {
	i := 0
	for i < len(s) && (s[i] <= 0x20) {
		i++
	}
	return s[i:]
}

// executableScriptTypes is the WHATWG-defined set of JavaScript MIME types
// that browsers treat as executable in <script> tags.
// Ref: https://mimesniff.spec.whatwg.org/#javascript-mime-type
var executableScriptTypes = map[string]struct{}{
	"":                            {}, // no type attribute = JS
	"text/javascript":             {},
	"application/javascript":      {},
	"text/ecmascript":             {},
	"application/ecmascript":      {},
	"application/x-javascript":    {},
	"application/x-ecmascript":    {},
	"text/javascript1.0":          {},
	"text/javascript1.1":          {},
	"text/javascript1.2":          {},
	"text/javascript1.3":          {},
	"text/javascript1.4":          {},
	"text/javascript1.5":          {},
	"text/jscript":                {},
	"text/livescript":             {},
	"text/x-ecmascript":           {},
	"text/x-javascript":           {},
	"module":                      {},
}

// isExecutableScriptTag determines from the raw <script ...> tag whether the
// script block contains executable JavaScript. Uses the WHATWG whitelist of
// JavaScript MIME types — any unrecognised type is a data block.
//
// The type= attribute is matched with a word-boundary check to avoid false
// positives on attributes like data-type=.
func isExecutableScriptTag(rawToken string) bool {
	rawLower := strings.ToLower(rawToken)

	typeIdx := -1
	search := rawLower
	offset := 0
	for {
		idx := strings.Index(search, "type")
		if idx < 0 {
			break
		}
		absIdx := offset + idx
		if absIdx > 0 {
			before := rawLower[absIdx-1]
			if before != ' ' && before != '\t' && before != '\n' && before != '\r' && before != '<' {
				offset = absIdx + 4
				search = rawLower[offset:]
				continue
			}
		}
		rest := rawLower[absIdx+4:]
		trimmed := strings.TrimLeft(rest, " \t\n\r")
		if strings.HasPrefix(trimmed, "=") {
			typeIdx = absIdx
			break
		}
		offset = absIdx + 4
		search = rawLower[offset:]
	}

	if typeIdx < 0 {
		return true
	}

	rest := rawLower[typeIdx+4:]
	rest = strings.TrimLeft(rest, " \t\n\r")
	if len(rest) == 0 || rest[0] != '=' {
		return true
	}
	rest = rest[1:]
	rest = strings.TrimLeft(rest, " \t\n\r")
	if len(rest) == 0 {
		return true
	}

	var typeVal string
	switch rest[0] {
	case '"', '\'':
		quote := rest[0]
		inner := rest[1:]
		end := strings.IndexByte(inner, quote)
		if end < 0 {
			typeVal = inner
		} else {
			typeVal = inner[:end]
		}
	default:
		end := strings.IndexAny(rest, " \t\n\r/>")
		if end < 0 {
			typeVal = rest
		} else {
			typeVal = rest[:end]
		}
	}

	// Extract MIME essence: strip parameters like ";charset=utf-8"
	if semi := strings.IndexByte(typeVal, ';'); semi >= 0 {
		typeVal = typeVal[:semi]
	}
	typeVal = strings.TrimSpace(typeVal)
	_, executable := executableScriptTypes[typeVal]
	return executable
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
// Handles whitespace around '=' (e.g., `value = '...'`).
func detectAttrQuoting(rawToken, attrName string) (byte, bool) {
	rawLower := strings.ToLower(rawToken)
	attrLower := strings.ToLower(attrName)

	offset := 0
	for {
		idx := strings.Index(rawLower[offset:], attrLower)
		if idx < 0 {
			break
		}
		absIdx := offset + idx

		// Verify word boundary before match to avoid matching e.g. "data-value" for "value"
		if absIdx > 0 {
			before := rawLower[absIdx-1]
			if before != ' ' && before != '\t' && before != '\n' && before != '\r' && before != '<' {
				offset = absIdx + len(attrLower)
				continue
			}
		}

		rest := rawLower[absIdx+len(attrLower):]
		trimmed := strings.TrimLeft(rest, " \t\n\r")
		if len(trimmed) == 0 || trimmed[0] != '=' {
			offset = absIdx + len(attrLower)
			continue
		}

		// Skip past '=' and optional whitespace in the original raw token
		eqOffset := absIdx + len(attrLower) + (len(rest) - len(trimmed)) + 1
		afterEq := strings.TrimLeft(rawToken[eqOffset:], " \t\n\r")
		if len(afterEq) == 0 {
			return '"', false
		}
		switch afterEq[0] {
		case '"':
			return '"', false
		case '\'':
			return '\'', false
		default:
			return 0, true
		}
	}
	return '"', false
}

// BestReflection returns the highest-priority reflection from the list.
// ContextNone reflections are skipped as they are not exploitable.
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
