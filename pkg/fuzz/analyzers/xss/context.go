package xss

import (
	"strings"

	"golang.org/x/net/html"
)

// DetectReflections parses the HTML body and returns all reflection contexts
// where the marker is found.
func DetectReflections(body string, marker string) []ReflectionInfo {
	markerLower := strings.ToLower(marker)

	// Bug fix #3: use case-insensitive check for the early-exit guard so that
	// server-side case transformations (e.g. uppercasing the canary) are still
	// detected instead of silently returning nil.
	if !strings.Contains(strings.ToLower(body), markerLower) {
		return nil
	}

	var reflections []ReflectionInfo

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
				// Bug fix #2: only treat a <script> tag as executable JavaScript
				// when its type attribute is absent or set to a JS MIME type.
				// Non-executable types (application/json, text/template, etc.)
				// must NOT set inScript so their text content is not classified
				// as an exploitable script context.
				if isExecutableScriptTag(rawToken) {
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
							// Event handler attributes (onclick, onerror, …) contain JavaScript
							ctx = ContextScript
						} else if isURLAttribute(attrName) && hasJavaScriptScheme(attrVal) {
							// Bug fix #1: a javascript: URI inside a URL attribute (href,
							// src, action, formaction, …) is executable JavaScript, not a
							// plain attribute injection.  Classify it as ContextScript so
							// the analyser selects JS-specific payloads instead of HTML
							// attribute break-out payloads.
							ctx = ContextScript
						} else if attrName == "srcdoc" {
							// Bug fix #4: the srcdoc attribute value is parsed as a full
							// HTML document by the browser.  Injection here is equivalent
							// to HTML text injection and warrants HTML-break-out payloads.
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

// isURLAttribute returns true for HTML attributes whose values are treated as
// URLs by browsers.  Injection of a javascript: URI into these attributes
// constitutes a JavaScript execution context.
func isURLAttribute(name string) bool {
	_, ok := urlAttributes[name]
	return ok
}

// urlAttributes lists HTML attributes whose values are treated as URLs.
var urlAttributes = map[string]struct{}{
	"href":       {},
	"src":        {},
	"action":     {},
	"formaction": {},
	"data":       {},
	"poster":     {},
	"ping":       {},
	"manifest":   {},
	"codebase":   {},
	"cite":       {},
	"longdesc":   {},
	"profile":    {},
	"usemap":     {},
	"classid":    {},
	"background": {},
}

// hasJavaScriptScheme reports whether the attribute value begins with the
// javascript: URI scheme (case-insensitive, with optional whitespace/control
// chars that browsers strip before interpreting the scheme).
func hasJavaScriptScheme(val string) bool {
	// Browsers strip leading whitespace and C0 control characters
	trimmed := strings.TrimLeftFunc(val, func(r rune) bool {
		return r <= 0x20
	})
	return strings.HasPrefix(strings.ToLower(trimmed), "javascript:")
}

// isExecutableScriptTag returns true if the <script> tag's type attribute
// indicates executable JavaScript (or is absent, which defaults to JS).
//
// Non-executable types that should NOT set inScript:
//   - application/json
//   - application/ld+json
//   - text/template  (used by many template frameworks)
//   - text/x-template
//   - text/html
//   - text/plain
//   - Any other type not in the executable set
func isExecutableScriptTag(rawToken string) bool {
	rawLower := strings.ToLower(rawToken)

	typeIdx := strings.Index(rawLower, "type=")
	if typeIdx < 0 {
		// No type attribute → defaults to text/javascript → executable
		return true
	}

	afterType := rawLower[typeIdx+5:]
	var typeVal string

	switch {
	case strings.HasPrefix(afterType, `"`):
		end := strings.Index(afterType[1:], `"`)
		if end >= 0 {
			typeVal = afterType[1 : end+1]
		}
	case strings.HasPrefix(afterType, `'`):
		end := strings.Index(afterType[1:], `'`)
		if end >= 0 {
			typeVal = afterType[1 : end+1]
		}
	default:
		// Unquoted attribute value ends at whitespace or >
		fields := strings.FieldsFunc(afterType, func(r rune) bool {
			return r == ' ' || r == '\t' || r == '>' || r == '/'
		})
		if len(fields) > 0 {
			typeVal = fields[0]
		}
	}

	return isExecutableScriptType(strings.TrimSpace(typeVal))
}

// isExecutableScriptType returns true for MIME types that cause a browser to
// execute the script contents as JavaScript.
func isExecutableScriptType(t string) bool {
	switch t {
	case "",
		"text/javascript",
		"text/ecmascript",
		"text/javascript1.0",
		"text/javascript1.1",
		"text/javascript1.2",
		"text/javascript1.3",
		"text/javascript1.4",
		"text/javascript1.5",
		"text/jscript",
		"text/livescript",
		"text/x-javascript",
		"text/x-ecmascript",
		"application/javascript",
		"application/ecmascript",
		"application/x-javascript",
		"application/x-ecmascript",
		"module":
		return true
	default:
		return false
	}
}
