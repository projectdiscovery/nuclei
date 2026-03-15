package xss

import (
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// DetectReflections parses the HTML body and returns all reflection contexts
// where the marker is found.
func DetectReflections(body string, marker string) []ReflectionInfo {
	// Use case-insensitive check so we don't miss reflections where the
	// server transforms the case of the reflected value.
	if !strings.Contains(strings.ToLower(body), strings.ToLower(marker)) {
		return nil
	}

	var reflections []ReflectionInfo
	markerLower := strings.ToLower(marker)

	tokenizer := html.NewTokenizer(strings.NewReader(body))

	var tagStack []string
	inScript := false
	inNonExecScript := false // true for <script type="application/json"> etc.
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
				// Check if this is a non-executable script type (e.g. application/json,
				// application/ld+json, importmap). These don't execute as JavaScript.
				inNonExecScript = isNonExecutableScriptType(rawToken)
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
						} else if isJavascriptURI(attrName, attrVal) {
							// javascript: URIs in href/src/action/formaction execute as script
							ctx = ContextScript
						} else if attrName == "srcdoc" {
							// srcdoc contains full HTML rendered in an iframe — treat as HTML injection
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
				inNonExecScript = false
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
				var ctx Context
				if inNonExecScript {
					// Non-executable script types (application/json, application/ld+json, etc.)
					// Use a distinct context so verifier can still try </script> breakouts.
					ctx = ContextNonExecutableScript
				} else {
					ctx = detectScriptStringContext(text, marker)
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

// detectScriptStringContext determines if the marker is inside a JS string literal,
// a JS comment (// or /* */), a regex literal (/pattern/), or in bare script code.
func detectScriptStringContext(scriptContent, marker string) Context {
	markerLower := strings.ToLower(marker)
	contentLower := strings.ToLower(scriptContent)

	idx := strings.Index(contentLower, markerLower)
	if idx < 0 {
		return ContextScript
	}

	// Walk through the script content tracking quote, comment, and regex state.
	inSingleQuote := false
	inDoubleQuote := false
	inBacktick := false
	inLineComment := false
	inBlockComment := false
	inRegex := false
	escaped := false

	// lastSignificantChar tracks the last non-whitespace character outside of
	// strings/comments/regex for determining if '/' starts a regex literal.
	lastSignificantChar := byte(0)
	// lastWord accumulates the current identifier/keyword token for regex
	// disambiguation. When we encounter '/' after a keyword like "return",
	// "typeof", etc., it's a regex, not division.
	var lastWord []byte

	for i := 0; i < idx; i++ {
		ch := scriptContent[i]

		// Handle line comment: everything until newline is ignored.
		if inLineComment {
			if ch == '\n' || ch == '\r' {
				inLineComment = false
			}
			continue
		}

		// Handle block comment: everything until */ is ignored.
		if inBlockComment {
			if ch == '*' && i+1 < len(scriptContent) && scriptContent[i+1] == '/' {
				inBlockComment = false
				i++ // skip the '/'
			}
			continue
		}

		// Handle regex literal: scan until unescaped closing '/'.
		if inRegex {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '/' {
				inRegex = false
			}
			continue
		}

		// Handle string literals.
		if inSingleQuote || inDoubleQuote || inBacktick {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			switch {
			case inSingleQuote && ch == '\'':
				inSingleQuote = false
			case inDoubleQuote && ch == '"':
				inDoubleQuote = false
			case inBacktick && ch == '`':
				inBacktick = false
			}
			continue
		}

		// Outside any string/comment/regex — handle transitions.
		if escaped {
			escaped = false
			continue
		}

		// Check for comment start: // or /*
		if ch == '/' && i+1 < idx {
			next := scriptContent[i+1]
			if next == '/' {
				inLineComment = true
				i++ // skip second '/'
				continue
			}
			if next == '*' {
				inBlockComment = true
				i++ // skip '*'
				continue
			}
		}

		// Check for regex literal start.
		// '/' is a regex delimiter when not preceded by a value expression.
		if ch == '/' {
			if isRegexPreceding(lastSignificantChar, lastWord) {
				inRegex = true
				continue
			}
			// Otherwise it's a division operator — update lastSignificantChar and continue.
		}

		switch ch {
		case '\'':
			inSingleQuote = true
			continue
		case '"':
			inDoubleQuote = true
			continue
		case '`':
			inBacktick = true
			continue
		case '\\':
			escaped = true
			continue
		}

		// Track last significant (non-whitespace) character for regex detection.
		if ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r' {
			lastSignificantChar = ch
			if isIdentChar(ch) {
				lastWord = append(lastWord, ch)
			} else {
				lastWord = lastWord[:0]
			}
		}
	}

	if inSingleQuote || inDoubleQuote || inBacktick {
		return ContextScriptString
	}
	if inLineComment || inBlockComment || inRegex {
		return ContextScriptComment
	}
	return ContextScript
}

// regexPrecedingKeywords are JavaScript keywords after which '/' starts a
// regex literal, not a division. These keywords cannot produce a value on
// the left-hand side of a division operator.
var regexPrecedingKeywords = map[string]struct{}{
	"return":     {},
	"typeof":     {},
	"void":       {},
	"delete":     {},
	"throw":      {},
	"new":        {},
	"in":         {},
	"instanceof": {},
	"case":       {},
	"yield":      {},
	"await":      {},
}

// isRegexPreceding returns true if the context preceding a '/' suggests the
// '/' begins a regex literal rather than being a division operator.
func isRegexPreceding(ch byte, lastWord []byte) bool {
	if ch == 0 {
		// Start of content — '/' is a regex.
		return true
	}

	// If the last significant char is an identifier char, check if the
	// accumulated word is a keyword that precedes regex.
	if isIdentChar(ch) {
		if len(lastWord) > 0 {
			_, isKeyword := regexPrecedingKeywords[strings.ToLower(string(lastWord))]
			return isKeyword
		}
		return false
	}

	// Closing paren/bracket — result of expression, so '/' is division.
	if ch == ')' || ch == ']' {
		return false
	}

	// Everything else (operators like =, ;, (, {, [, !, &, |, etc.) precedes regex.
	return true
}

// isIdentChar returns true if ch is a valid JavaScript identifier character.
func isIdentChar(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9') || ch == '_' || ch == '$'
}

// detectAttrQuoting detects the quoting style of an attribute from raw HTML.
// Returns the quote character and whether the attribute is unquoted.
// Uses regex with word boundary for exact attribute name matching and handles
// spaces around =.
func detectAttrQuoting(rawToken, attrName string) (byte, bool) {
	// Build a regex that matches the exact attribute name (word boundary) with
	// optional spaces around '=' followed by the quote or value.
	pattern := `(?i)\b` + regexp.QuoteMeta(attrName) + `\s*=\s*(.)`
	re := regexp.MustCompile(pattern)
	m := re.FindStringSubmatch(rawToken)
	if m == nil {
		return '"', false // default to double-quoted
	}
	ch := m[1][0]
	switch ch {
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
