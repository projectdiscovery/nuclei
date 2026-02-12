package xss

import (
	"strings"

	"golang.org/x/net/html"
)

// DetectReflections tokenizes an HTML response body and returns all locations
// where the marker appears, classified by HTML parsing context. Results are
// capped at maxReflections to avoid pathological inputs.
func DetectReflections(body, marker string) []ReflectionInfo {
	if body == "" || marker == "" || !strings.Contains(body, marker) {
		return nil
	}

	tokenizer := html.NewTokenizer(strings.NewReader(body))
	stack := make([]string, 0, 8)
	reflections := make([]ReflectionInfo, 0, 4)
	tokenOffset := 0

	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			break
		}

		raw := string(tokenizer.Raw())
		token := tokenizer.Token()

		switch tokenType {
		case html.StartTagToken:
			tagName := strings.ToLower(token.Data)
			reflections = append(reflections, findAttributeReflections(raw, token.Attr, marker, tokenOffset)...)
			stack = append(stack, tagName)

		case html.SelfClosingTagToken:
			reflections = append(reflections, findAttributeReflections(raw, token.Attr, marker, tokenOffset)...)

		case html.EndTagToken:
			closingTag := strings.ToLower(token.Data)
			for i := len(stack) - 1; i >= 0; i-- {
				if stack[i] == closingTag {
					stack = stack[:i]
					break
				}
			}

		case html.TextToken:
			if !strings.Contains(token.Data, marker) {
				tokenOffset += len(raw)
				continue
			}
			ctx := classifyTextContext(currentTag(stack), token.Data, marker)
			chars := DetectAvailableChars(token.Data, marker)
			startIdx := tokenOffset + strings.Index(raw, marker)
			reflections = append(reflections, reflectionForContext(ctx, "", chars, startIdx, startIdx+len(marker)))

		case html.CommentToken:
			if strings.Contains(token.Data, marker) {
				chars := DetectAvailableChars(token.Data, marker)
				startIdx := tokenOffset + strings.Index(raw, marker)
				reflections = append(reflections, reflectionForContext(ContextComment, "", chars, startIdx, startIdx+len(marker)))
			}
		}
		tokenOffset += len(raw)

		if len(reflections) >= maxReflections {
			break
		}
	}

	// Drain: catch reflections in malformed/truncated HTML that the tokenizer
	// didn't fully parse (e.g. unclosed tags at end of document).
	reflections = drainRemainingReflections(body, marker, reflections)

	return reflections
}

// drainRemainingReflections scans for marker occurrences that the tokenizer
// may have missed due to malformed HTML (unclosed tags, truncated documents).
func drainRemainingReflections(body, marker string, existing []ReflectionInfo) []ReflectionInfo {
	if len(existing) >= maxReflections {
		return existing
	}
	// Count marker occurrences in body vs found reflections
	bodyCount := strings.Count(body, marker)
	if bodyCount <= len(existing) {
		return existing
	}
	// There are unfound reflections — add them as HTMLText (conservative fallback)
	missing := bodyCount - len(existing)
	if missing+len(existing) > maxReflections {
		missing = maxReflections - len(existing)
	}
	chars := DetectAvailableChars(body, marker)
	for i := 0; i < missing; i++ {
		existing = append(existing, reflectionForContext(ContextHTMLText, "", chars, -1, -1))
	}
	return existing
}

// currentTag returns the innermost open tag from the tokenizer stack.
func currentTag(stack []string) string {
	if len(stack) == 0 {
		return ""
	}
	return stack[len(stack)-1]
}

// classifyTextContext determines text-node context based on the current tag.
func classifyTextContext(tagName, text, marker string) ContextType {
	switch tagName {
	case "script":
		return classifyScriptContext(text, marker)
	case "textarea", "title":
		return ContextRCDATA
	case "style":
		return ContextStyle
	default:
		return ContextHTMLText
	}
}

// classifyScriptContext detects whether a marker appears in script block code
// or inside a string/template literal.
func classifyScriptContext(scriptText, marker string) ContextType {
	pos := strings.Index(scriptText, marker)
	if pos < 0 {
		return ContextScriptBlock
	}

	var quote rune
	var braceStack []bool // true = entered from template interpolation
	escaped := false

	for i := 0; i < pos; i++ {
		ch := rune(scriptText[i])
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}

		if quote != 0 {
			if ch == quote {
				quote = 0
				continue
			}
			if quote == '`' && ch == '$' && i+1 < pos && scriptText[i+1] == '{' {
				// Enter interpolation: ${
				quote = 0
				braceStack = append(braceStack, true)
				i++ // skip {
			}
			continue
		}

		// Not in quote
		switch ch {
		case '"', '\'', '`':
			quote = ch
		case '{':
			braceStack = append(braceStack, false)
		case '}':
			if len(braceStack) > 0 {
				fromTemplate := braceStack[len(braceStack)-1]
				braceStack = braceStack[:len(braceStack)-1]
				if fromTemplate {
					quote = '`'
				}
			}
		}
	}

	switch quote {
	case '"':
		return ContextScriptStringDouble
	case '\'':
		return ContextScriptStringSingle
	case '`':
		return ContextScriptTemplate
	default:
		return ContextScriptBlock
	}
}

// findAttributeReflections identifies marker reflections inside tag attributes
// and classifies each reflection by quoting and attribute type.
func findAttributeReflections(raw string, attrs []html.Attribute, marker string, baseOffset int) []ReflectionInfo {
	results := make([]ReflectionInfo, 0, 2)
	lastIndex := 0
	rawLower := strings.ToLower(raw)

	for _, attr := range attrs {
		if !strings.Contains(attr.Val, marker) {
			continue
		}

		// Calculate the start search position for this attribute
		// We can't rely just on the previous attr's end, because attributes can be reordered by parser vs raw?
		// Actually html.Tokenizer.Raw() gives the exact raw tag.
		// So we can search sequentially.

		// Fallback to simple search if we can't reliably track
		// But the request specifically asks to "compute the offset of the marker for the current attr"
		// and "search raw starting from the last seen index"

		idx := strings.Index(rawLower[lastIndex:], strings.ToLower(attr.Key))
		searchFrom := 0
		if idx >= 0 {
			searchFrom = lastIndex + idx
		}

		ctx := classifyAttributeContext(raw, attr, marker, searchFrom)

		// Update lastIndex to avoid re-matching the same attribute (generic approximation)
		// Ideally classifyAttributeContext would return the end index.
		// For now, we update it if we found the key.
		if idx >= 0 {
			lastIndex = searchFrom + len(attr.Key)
		}

		// Event handler attributes get a distinct context type
		if isEventHandler(attr.Key) {
			ctx = ContextEventHandler
		} else if isURLAttribute(attr.Key) && ctx != ContextAttributeUnquoted {
			ctx = ContextURLAttribute
		}

		chars := DetectAvailableChars(attr.Val, marker)
		// Approximate start/end calculation:
		// We know 'searchFrom' points to start of Key.
		// Detailed location inside value is tricky due to quotes/spaces.
		// For simplicity/robustness, we can point to the attribute value's rough location.
		// But wait, we need detection encoding window.
		// Let's refine:
		// We have `attr.Val` which contains marker.
		// We can find marker in `attr.Val`?
		// But we need offset in `raw`.
		// `classifyAttributeContext` logic parses `raw`.
		// Let's just use a window around the attribute for now?
		// No, better to search marker in `raw` after `searchFrom` + `len(attr.Key)`.

		valIdx := strings.Index(rawLower[searchFrom:], strings.ToLower(marker))
		startIdx := -1
		endIdx := -1
		if valIdx >= 0 {
			startIdx = baseOffset + searchFrom + valIdx
			endIdx = startIdx + len(marker)
		}

		info := reflectionForContext(ctx, attr.Key, chars, startIdx, endIdx)
		results = append(results, info)
	}
	return results
}

// classifyAttributeContext determines whether the marker is reflected in a
// double-quoted, single-quoted, or unquoted attribute value.
func classifyAttributeContext(rawToken string, attr html.Attribute, marker string, searchFrom int) ContextType {
	attrKey := strings.ToLower(attr.Key)
	rawLower := strings.ToLower(rawToken)
	// searchFrom is passed in now

	for {
		offset := strings.Index(rawLower[searchFrom:], attrKey)
		if offset < 0 {
			break
		}
		keyPos := searchFrom + offset

		if keyPos > 0 {
			prev := rawToken[keyPos-1]
			if !isHTMLSpace(prev) && prev != '<' {
				searchFrom = keyPos + len(attrKey)
				continue
			}
		}

		i := keyPos + len(attrKey)
		for i < len(rawToken) && isHTMLSpace(rawToken[i]) {
			i++
		}
		if i >= len(rawToken) || rawToken[i] != '=' {
			searchFrom = keyPos + len(attrKey)
			continue
		}
		i++
		for i < len(rawToken) && isHTMLSpace(rawToken[i]) {
			i++
		}
		if i >= len(rawToken) {
			return ContextAttributeUnquoted
		}

		switch rawToken[i] {
		case '"':
			start := i + 1
			end := start
			for end < len(rawToken) && rawToken[end] != '"' {
				end++
			}
			if strings.Contains(rawToken[start:end], marker) {
				return ContextAttributeDoubleQuoted
			}
		case '\'':
			start := i + 1
			end := start
			for end < len(rawToken) && rawToken[end] != '\'' {
				end++
			}
			if strings.Contains(rawToken[start:end], marker) {
				return ContextAttributeSingleQuoted
			}
		default:
			start := i
			end := start
			for end < len(rawToken) && !isHTMLSpace(rawToken[end]) && rawToken[end] != '>' {
				end++
			}
			if strings.Contains(rawToken[start:end], marker) {
				return ContextAttributeUnquoted
			}
		}

		searchFrom = keyPos + len(attrKey)
	}

	return classifyAttributeContextByMarker(rawToken, marker)
}

// classifyAttributeContextByMarker infers attribute quoting directly from the
// marker location when per-attribute parsing fails.
func classifyAttributeContextByMarker(rawToken, marker string) ContextType {
	markerPos := strings.Index(rawToken, marker)
	if markerPos < 0 {
		return ContextAttributeUnquoted
	}
	eqPos := strings.LastIndex(rawToken[:markerPos], "=")
	if eqPos < 0 {
		return ContextAttributeUnquoted
	}
	i := eqPos + 1
	for i < len(rawToken) && isHTMLSpace(rawToken[i]) {
		i++
	}
	if i >= len(rawToken) {
		return ContextAttributeUnquoted
	}
	switch rawToken[i] {
	case '"':
		return ContextAttributeDoubleQuoted
	case '\'':
		return ContextAttributeSingleQuoted
	default:
		return ContextAttributeUnquoted
	}
}

// isHTMLSpace reports whether a byte is one of the HTML ASCII whitespace chars.
func isHTMLSpace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'
}

// reflectionForContext builds reflection metadata and assigns execution priority
// so high-impact contexts are attempted first.
func reflectionForContext(ctx ContextType, attrName string, chars CharacterSet, start, end int) ReflectionInfo {
	priority := 100
	switch ctx {
	case ContextScriptBlock, ContextScriptStringDouble, ContextScriptStringSingle, ContextScriptTemplate:
		priority = 10
	case ContextEventHandler:
		priority = 12
	case ContextURLAttribute:
		priority = 15
	case ContextAttributeUnquoted:
		priority = 20
	case ContextAttributeDoubleQuoted, ContextAttributeSingleQuoted:
		priority = 30
	case ContextHTMLText:
		priority = 40
	case ContextRCDATA:
		priority = 50
	case ContextComment:
		priority = 60
	case ContextStyle:
		priority = 70
	default:
		priority = 80
	}
	return ReflectionInfo{
		Context:        ctx,
		AvailableChars: chars,
		AttributeName:  strings.ToLower(attrName),
		PriorityWeight: priority,
		StartIndex:     start,
		EndIndex:       end,
	}
}
