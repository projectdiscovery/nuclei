package xss

import (
	"strings"

	"golang.org/x/net/html"
)

// DetectReflections parses the HTML body and returns all reflection contexts
// where the marker is found.
func DetectReflections(body string, marker string) []ReflectionInfo {
	markerLower := strings.ToLower(marker)

	// Fix #3: case-insensitive initial check to catch transformed reflections
	if !strings.Contains(strings.ToLower(body), markerLower) {
		return nil
	}

	var reflections []ReflectionInfo

	tokenizer := html.NewTokenizer(strings.NewReader(body))

	var tagStack []string
	inScript := false       // true when inside ANY <script> raw-text block
	executableScript := false // true only when inside a JS-executable <script>
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
				// The HTML parser always treats <script> content as raw text,
				// regardless of the type attribute. A non-executable data block
				// (e.g. <script type="application/json">) is still a raw-text
				// element: injecting </script> will break out of it. Track both
				// states so selectPayloads() can emit the right payload family.
				inScript = true
				executableScript = isExecutableScriptTag(rawToken)
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
						} else if isJavascriptURI(attrVal) {
							// Fix #1: javascript: URI scheme = script execution context.
							// Browsers strip leading whitespace before the scheme, so
							// "  javascript:alert()" is also executable.
							ctx = ContextScript
						} else if isDataHTMLURI(attrVal) {
							// data:text/html URIs are equally dangerous — the browser
							// renders their payload as a full HTML document.
							ctx = ContextScript
						} else if attrName == "srcdoc" {
							// Fix #4: srcdoc allows full HTML injection
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
				executableScript = false
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
				// For executable <script> blocks, detect whether the marker
				// lands inside a string literal (drives quote-escape payloads).
				// For non-executable data blocks (e.g. application/json), the
				// browser's HTML parser still treats the content as raw text, so
				// </script> injection is a live XSS sink → emit ContextScript so
				// selectPayloads() considers the breakout payload family.
				ctx := ContextScript
				if executableScript {
					ctx = detectScriptStringContext(text, marker)
				}
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

// isJavascriptURI reports whether attrVal is a javascript: URI.
// Browsers strip ASCII whitespace before comparing the scheme, so
// "\t javascript:alert()" is executable too.
func isJavascriptURI(attrVal string) bool {
	return strings.HasPrefix(strings.TrimSpace(strings.ToLower(attrVal)), "javascript:")
}

// isDataHTMLURI reports whether attrVal is a data: URI whose MIME type can
// execute JavaScript or inject HTML. Browsers can execute the following:
//   - data:text/html          – full HTML document (arbitrary JS via <script>)
//   - data:text/javascript    – direct JS execution (e.g. <iframe src=...>)
//   - data:application/javascript – same
//   - data:image/svg+xml      – SVG with inline event handlers / <script>
//
// The media type is parsed exactly (up to the first ';' or ',' delimiter) so
// that invalid types like data:text/htmlfoo or data:text/javascriptx are not
// falsely matched.
func isDataHTMLURI(attrVal string) bool {
	lower := strings.ToLower(strings.TrimSpace(attrVal))
	if !strings.HasPrefix(lower, "data:") {
		return false
	}

	// Extract the media type: everything between "data:" and the first ';' or ','
	mediaType := strings.TrimPrefix(lower, "data:")
	if end := strings.IndexAny(mediaType, ";,"); end >= 0 {
		mediaType = mediaType[:end]
	}

	switch mediaType {
	case "text/html", "text/javascript", "application/javascript", "image/svg+xml":
		return true
	default:
		return false
	}
}

// isExecutableScriptTag returns true if a <script> tag should be treated as
// executable JavaScript. Non-executable types (e.g. application/json,
// text/template) must not be flagged as script context.
//
// Fix #2: <script type="application/json"> should NOT be ContextScript.
func isExecutableScriptTag(rawToken string) bool {
	rawLower := strings.ToLower(rawToken)

	// Find the word-boundary "type" attribute: must be preceded by whitespace
	// or the opening '<', and followed by optional whitespace then '='.
	// A plain Index("type=") can match "data-type=" — use a small scanner
	// that checks the character before the match.
	typeIdx := -1
	search := rawLower
	offset := 0
	for {
		idx := strings.Index(search, "type")
		if idx < 0 {
			break
		}
		absIdx := offset + idx
		// The char immediately before must be whitespace or '<'
		if absIdx > 0 {
			before := rawLower[absIdx-1]
			if before != ' ' && before != '\t' && before != '\n' && before != '\r' && before != '<' {
				offset = absIdx + 4
				search = rawLower[offset:]
				continue
			}
		}
		// After "type" there may be optional whitespace then '='
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
		// No type attribute — default is executable JavaScript
		return true
	}

	// Skip past "type", optional whitespace, and "="
	rest := rawLower[typeIdx+4:]
	rest = strings.TrimLeft(rest, " \t\n\r")
	if len(rest) == 0 || rest[0] != '=' {
		return true
	}
	rest = rest[1:] // skip '='

		// rest now starts with optional whitespace then '=' then the value
	// (the '=' was already consumed above; rest == value portion)
	rest = strings.TrimLeft(rest, " \t\n\r")

	var typeVal string
	if len(rest) == 0 {
		return true
	}
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
		// Unquoted value
		end := strings.IndexAny(rest, " \t\n\r/>")
		if end < 0 {
			typeVal = rest
		} else {
			typeVal = rest[:end]
		}
	}

	// Per WHATWG HTML spec, only recognised JavaScript MIME types are executed.
	// Everything else (unknown types, data formats, templates, …) is treated as
	// a data block and MUST NOT be flagged as ContextScript.
	// Ref: https://mimesniff.spec.whatwg.org/#javascript-mime-type
	executableTypes := []string{
		"text/javascript",
		"text/ecmascript",
		"text/jscript",
		"text/livescript",
		"text/x-javascript",
		"text/x-ecmascript",
		"application/javascript",
		"application/ecmascript",
		"application/x-javascript",
		"application/x-ecmascript",
		"module", // ES module shorthand accepted by all modern browsers
	}
	for _, mime := range executableTypes {
		if typeVal == mime {
			return true
		}
	}

	// Unknown or unrecognised type → browser treats as data block, not executable
	return false
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
	rawLower := strings.ToLower(rawToken)
	attrNameLower := strings.ToLower(attrName)
	
	// Search for attribute name with proper word boundaries
	// The attribute name must be preceded by whitespace or '<'
	// and followed by optional whitespace then '='
	search := rawLower
	offset := 0
	for {
		idx := strings.Index(search, attrNameLower)
		if idx < 0 {
			return '"', false // default to double-quoted if not found
		}
		
		absIdx := offset + idx
		
		// Check character before attribute name (must be whitespace or '<')
		if absIdx > 0 {
			before := rawLower[absIdx-1]
			if before != ' ' && before != '\t' && before != '\n' && before != '\r' && before != '<' {
				offset = absIdx + len(attrNameLower)
				search = rawLower[offset:]
				continue
			}
		}
		
		// Check what follows the attribute name
		afterAttr := absIdx + len(attrNameLower)
		if afterAttr >= len(rawLower) {
			return '"', false
		}
		
		// Skip optional whitespace after attribute name
		rest := rawLower[afterAttr:]
		trimmed := strings.TrimLeft(rest, " \t\n\r")
		if !strings.HasPrefix(trimmed, "=") {
			// Not followed by '=', keep searching
			offset = absIdx + len(attrNameLower)
			search = rawLower[offset:]
			continue
		}
		
		// Found valid attribute assignment
		// Skip past whitespace and '=' to find quote character
		eqPos := afterAttr + (len(rest) - len(trimmed))
		afterEq := eqPos + 1
		if afterEq >= len(rawToken) {
			return '"', false
		}
		
		// Skip optional whitespace after '='
		for afterEq < len(rawToken) && (rawToken[afterEq] == ' ' || rawToken[afterEq] == '\t' || rawToken[afterEq] == '\n' || rawToken[afterEq] == '\r') {
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
