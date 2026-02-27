package xss

import (
	"bytes"
	"strings"

	"golang.org/x/net/html"
)

// Package-level byte slices to avoid per-call heap allocation in the
// hot tokenizer loop.
var (
	scriptTag = []byte("script")
	styleTag  = []byte("style")
	titleTag  = []byte("title")
	textareaT = []byte("textarea")
	onPrefix  = []byte("on")
)

// maxReflections caps how many reflection points we track per response
// to bound memory and CPU in pathological pages.
const maxReflections = 16

// DetectReflections walks the HTML response body using the standard
// tokenizer and returns metadata about every location where the marker
// string is reflected. The caller typically sends a canary value and
// passes it here as `marker`.
//
// The function handles:
//   - Text nodes (body content)
//   - Attribute values (quoted and unquoted)
//   - Script blocks (inline JS)
//   - Style blocks (inline CSS)
//   - RCDATA elements (title, textarea)
//   - Comments
//   - Event-handler attributes (classified as script context)
//
// When the HTML tokenizer fails to find a reflection that we know
// exists (malformed/truncated HTML), we fall back to substring
// scanning to avoid missing reflections.
func DetectReflections(body, marker string) []ReflectionInfo {
	if !strings.Contains(body, marker) {
		return nil
	}

	m := []byte(marker)
	z := html.NewTokenizer(strings.NewReader(body))

	var (
		reflections []ReflectionInfo
		tagStack    []string // tracks nesting for script/style/rcdata
	)

	currentContext := func() string {
		if len(tagStack) == 0 {
			return ""
		}
		return tagStack[len(tagStack)-1]
	}

	// Track how much of the body we have consumed so we can calculate
	// byte offsets for each reflection.
	bodyOffset := 0

	for {
		if len(reflections) >= maxReflections {
			break
		}

		tt := z.Next()
		raw := string(z.Raw())
		tokenLen := len(raw)

		switch tt {
		case html.ErrorToken:
			// End of document. Fall through to the drain logic.
			goto drain

		case html.CommentToken:
			if bytes.Contains(z.Text(), m) {
				chars := detectCharsNearMarker(body, marker, bodyOffset, tokenLen)
				reflections = append(reflections, ReflectionInfo{
					Context:  ContextHTMLComment,
					Position: bodyOffset + strings.Index(raw, marker),
					Chars:    chars,
				})
			}

		case html.StartTagToken, html.SelfClosingTagToken:
			tn, hasAttr := z.TagName()
			tagLower := strings.ToLower(string(tn))

			if tt == html.StartTagToken {
				switch {
				case bytes.EqualFold(tn, scriptTag):
					tagStack = append(tagStack, "script")
				case bytes.EqualFold(tn, styleTag):
					tagStack = append(tagStack, "style")
				case bytes.EqualFold(tn, titleTag), bytes.EqualFold(tn, textareaT):
					tagStack = append(tagStack, tagLower)
				}
			}

			// Check if marker appears in the raw tag (e.g. tag name injection)
			if hasAttr {
				reflections = findAttributeReflections(raw, z, marker, m, body, bodyOffset, tokenLen, reflections)
			}

		case html.EndTagToken:
			tn, _ := z.TagName()
			closingTag := strings.ToLower(string(tn))
			// Pop matching tag from the stack, searching from the top.
			for i := len(tagStack) - 1; i >= 0; i-- {
				if tagStack[i] == closingTag {
					tagStack = tagStack[:i]
					break
				}
			}

		case html.TextToken:
			text := z.Text()
			if bytes.Contains(text, m) {
				ctx := currentContext()
				chars := detectCharsNearMarker(body, marker, bodyOffset, tokenLen)
				var ctxType ContextType

				switch ctx {
				case "script":
					ctxType = classifyScriptContext(raw, marker)
				case "style":
					ctxType = ContextStyle
				case "title", "textarea":
					// RCDATA elements: content is not parsed as HTML
					ctxType = ContextHTMLText
				default:
					ctxType = ContextHTMLText
				}

				idx := strings.Index(raw, marker)
				if idx < 0 {
					// Marker may be entity-encoded in raw but decoded in Text
					idx = 0
				}
				reflections = append(reflections, ReflectionInfo{
					Context:  ctxType,
					Position: bodyOffset + idx,
					Chars:    chars,
				})
			}
		}

		bodyOffset += tokenLen
	}

drain:
	// If we know the marker is in the body but the tokenizer missed it
	// (truncated HTML, unclosed tags, etc.), scan the remaining text
	// with substring windows to pick up anything we missed.
	reflections = drainRemainingReflections(body, marker, reflections)
	return reflections
}

// findAttributeReflections examines the attributes of the current start
// tag for reflections of the marker. Event handler attributes are
// classified as ContextScript; other attributes are ContextAttribute
// or ContextAttributeUnquoted depending on the quoting style in the
// raw token string.
func findAttributeReflections(
	raw string,
	z *html.Tokenizer,
	marker string,
	m []byte,
	body string,
	bodyOffset, tokenLen int,
	reflections []ReflectionInfo,
) []ReflectionInfo {
	for {
		if len(reflections) >= maxReflections {
			break
		}
		k, v, more := z.TagAttr()

		if bytes.Contains(v, m) {
			attrName := strings.ToLower(string(k))
			chars := detectCharsNearMarker(body, marker, bodyOffset, tokenLen)

			if isEventHandler(k) {
				reflections = append(reflections, ReflectionInfo{
					Context:       ContextScript,
					Position:      bodyOffset,
					AttributeName: attrName,
					Chars:         chars,
				})
			} else {
				ctxType := classifyAttributeContext(raw, marker)
				reflections = append(reflections, ReflectionInfo{
					Context:       ctxType,
					Position:      bodyOffset,
					AttributeName: attrName,
					Chars:         chars,
				})
			}
		}

		// Also check if the marker is in the attribute name itself
		// (attribute injection).
		if bytes.Contains(k, m) {
			chars := detectCharsNearMarker(body, marker, bodyOffset, tokenLen)
			reflections = append(reflections, ReflectionInfo{
				Context:  ContextAttribute,
				Position: bodyOffset,
				Chars:    chars,
			})
		}

		if !more {
			break
		}
	}
	return reflections
}

// classifyAttributeContext looks at the raw HTML around the marker to
// determine whether the attribute is double-quoted, single-quoted, or
// unquoted. The distinction matters because breakout characters differ.
func classifyAttributeContext(raw, marker string) ContextType {
	idx := strings.Index(raw, marker)
	if idx < 0 {
		return ContextAttribute
	}

	// Walk backward from the marker to find the quote character (or lack
	// thereof) that opens this attribute value.
	for i := idx - 1; i >= 0; i-- {
		ch := raw[i]
		switch ch {
		case '"':
			return ContextAttribute
		case '\'':
			return ContextAttribute
		case '=':
			// '=' immediately before the marker with no quote means unquoted
			return ContextAttributeUnquoted
		case ' ', '\t', '\n', '\r':
			// Whitespace before an unquoted value
			return ContextAttributeUnquoted
		}
	}
	return ContextAttribute
}

// classifyScriptContext determines whether the marker inside a <script>
// block is inside a JS string literal or in bare script code. This
// distinction drives payload selection: string context needs a closing
// quote before executable code, while bare script context can inject
// directly.
func classifyScriptContext(raw, marker string) ContextType {
	idx := strings.Index(raw, marker)
	if idx < 0 {
		return ContextScript
	}

	// Walk the text before the marker, tracking quote state. We handle
	// single quotes, double quotes, backtick template literals, and
	// backslash escapes.
	var quote byte
	escaped := false
	for i := 0; i < idx; i++ {
		ch := raw[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' && quote != 0 {
			escaped = true
			continue
		}

		if quote == 0 {
			// Not inside a string: check for opening quote
			if ch == '\'' || ch == '"' || ch == '`' {
				quote = ch
			}
		} else if ch == quote {
			// Closing the current string
			quote = 0
		}
	}

	if quote != 0 {
		return ContextScriptString
	}
	return ContextScript
}

// detectCharsNearMarker extracts a window around the marker position in
// the body and runs character survival detection on that window. This is
// more precise than checking the entire body because unrelated page
// content naturally contains < > " ' etc.
func detectCharsNearMarker(body, marker string, tokenOffset, tokenLen int) CharacterSet {
	// Use the token boundaries as our detection window.
	start := tokenOffset
	end := tokenOffset + tokenLen
	if start < 0 {
		start = 0
	}
	if end > len(body) {
		end = len(body)
	}
	window := body[start:end]
	return DetectAvailableChars(window, marker)
}

// drainRemainingReflections picks up marker occurrences that the HTML
// tokenizer missed (e.g. because of severely malformed HTML or
// truncated responses). It scans the body with simple substring
// search and adds ContextHTMLText reflections for any positions not
// already covered by the tokenizer results.
func drainRemainingReflections(body, marker string, existing []ReflectionInfo) []ReflectionInfo {
	// Count total marker occurrences in the body.
	bodyCount := strings.Count(body, marker)
	if bodyCount <= len(existing) {
		return existing
	}

	// How many did we miss?
	missing := bodyCount - len(existing)
	if missing+len(existing) > maxReflections {
		missing = maxReflections - len(existing)
	}

	// Build a set of positions already found so we don't duplicate.
	found := make(map[int]struct{}, len(existing))
	for _, r := range existing {
		found[r.Position] = struct{}{}
	}

	// Scan for all occurrences and fill in the gaps.
	searchStart := 0
	for i := 0; i < missing; i++ {
		idx := strings.Index(body[searchStart:], marker)
		if idx < 0 {
			break
		}
		absPos := searchStart + idx
		searchStart = absPos + len(marker)

		if _, already := found[absPos]; already {
			// This position was already detected by the tokenizer.
			i--
			continue
		}

		chars := DetectAvailableChars(body, marker)
		existing = append(existing, ReflectionInfo{
			Context:  ContextHTMLText,
			Position: absPos,
			Chars:    chars,
		})
	}
	return existing
}
