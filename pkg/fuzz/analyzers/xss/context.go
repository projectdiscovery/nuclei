package xss

import (
	"strings"
)

// ReflectionContext describes the HTML context where a value is reflected.
type ReflectionContext int

const (
	ContextNone ReflectionContext = iota
	// ContextHTMLBody means the value appears between HTML tags (e.g. <div>VALUE</div>).
	ContextHTMLBody
	// ContextHTMLAttrDoubleQuoted means the value appears inside a double-quoted attribute.
	ContextHTMLAttrDoubleQuoted
	// ContextHTMLAttrSingleQuoted means the value appears inside a single-quoted attribute.
	ContextHTMLAttrSingleQuoted
	// ContextHTMLAttrUnquoted means the value appears inside an unquoted attribute.
	ContextHTMLAttrUnquoted
	// ContextScriptBlock means the value appears inside a <script> tag outside strings.
	ContextScriptBlock
	// ContextScriptStringDouble means the value appears inside a JS double-quoted string.
	ContextScriptStringDouble
	// ContextScriptStringSingle means the value appears inside a JS single-quoted string.
	ContextScriptStringSingle
	// ContextScriptTemplate means the value appears inside a JS template literal.
	ContextScriptTemplate
	// ContextHTMLComment means the value appears inside an HTML comment.
	ContextHTMLComment
	// ContextStyleBlock means the value appears inside a <style> tag.
	ContextStyleBlock
	// ContextURLAttribute means the value appears in an href, src, or action attribute.
	ContextURLAttribute
)

// String returns a human-readable label for the context.
func (c ReflectionContext) String() string {
	switch c {
	case ContextHTMLBody:
		return "html-body"
	case ContextHTMLAttrDoubleQuoted:
		return "html-attr-double-quoted"
	case ContextHTMLAttrSingleQuoted:
		return "html-attr-single-quoted"
	case ContextHTMLAttrUnquoted:
		return "html-attr-unquoted"
	case ContextScriptBlock:
		return "script-block"
	case ContextScriptStringDouble:
		return "script-string-double"
	case ContextScriptStringSingle:
		return "script-string-single"
	case ContextScriptTemplate:
		return "script-template"
	case ContextHTMLComment:
		return "html-comment"
	case ContextStyleBlock:
		return "style-block"
	case ContextURLAttribute:
		return "url-attribute"
	default:
		return "none"
	}
}

// BreakoutChars returns the characters that must be unescaped for this context
// to be exploitable.
func (c ReflectionContext) BreakoutChars() string {
	switch c {
	case ContextHTMLBody:
		return "<>"
	case ContextHTMLAttrDoubleQuoted:
		return "\""
	case ContextHTMLAttrSingleQuoted:
		return "'"
	case ContextHTMLAttrUnquoted:
		return " >"
	case ContextScriptBlock:
		return "</"
	case ContextScriptStringDouble:
		return "\"\\"
	case ContextScriptStringSingle:
		return "'\\"
	case ContextScriptTemplate:
		return "`${"
	case ContextHTMLComment:
		return "-->"
	case ContextStyleBlock:
		return "</"
	case ContextURLAttribute:
		return "javascript:"
	default:
		return ""
	}
}

// Reflection describes a single point where the canary was found in the response.
type Reflection struct {
	Context  ReflectionContext
	Position int
	// Surrounding is a snippet of the response around the reflection.
	Surrounding string
}

// urlAttributes are HTML attributes that accept URLs.
var urlAttributes = map[string]struct{}{
	"href":       {},
	"src":        {},
	"action":     {},
	"formaction": {},
	"data":       {},
	"poster":     {},
	"codebase":   {},
	"cite":       {},
	"background": {},
	"ping":       {},
}

// ClassifyReflections finds all occurrences of canary in the body and
// determines the HTML context of each reflection point.
func ClassifyReflections(body, canary string) []Reflection {
	if canary == "" || body == "" {
		return nil
	}

	lowerBody := asciiToLower(body)
	lowerCanary := asciiToLower(canary)

	var reflections []Reflection

	// Find all positions of the canary in the response
	positions := findAllPositions(lowerBody, lowerCanary)
	if len(positions) == 0 {
		return nil
	}

	for _, pos := range positions {
		ctx := classifyPosition(body, lowerBody, pos, lowerCanary)
		surrounding := extractSurrounding(body, pos, len(canary), 60)
		reflections = append(reflections, Reflection{
			Context:     ctx,
			Position:    pos,
			Surrounding: surrounding,
		})
	}
	return reflections
}

// findAllPositions returns all start indices of needle in haystack.
func findAllPositions(haystack, needle string) []int {
	var positions []int
	start := 0
	for {
		idx := strings.Index(haystack[start:], needle)
		if idx == -1 {
			break
		}
		positions = append(positions, start+idx)
		start += idx + 1
	}
	return positions
}

// extractSurrounding returns a snippet around position pos in body.
func extractSurrounding(body string, pos, canaryLen, window int) string {
	start := pos - window
	if start < 0 {
		start = 0
	}
	end := pos + canaryLen + window
	if end > len(body) {
		end = len(body)
	}
	return body[start:end]
}

// classifyPosition determines the HTML context at a given position.
func classifyPosition(body, lowerBody string, pos int, canary string) ReflectionContext {
	// Check if inside an HTML comment
	if isInsideHTMLComment(lowerBody, pos) {
		return ContextHTMLComment
	}

	// Check if inside a <script> tag
	if ctx, ok := classifyScriptContext(body, lowerBody, pos, canary); ok {
		return ctx
	}

	// Check if inside a <style> tag (ensure canary is in the body, not the attributes)
	if isInsideTag(lowerBody, pos, "style") {
		contentStart := findLastTagContentStart(lowerBody, pos, "style")
		if contentStart != -1 && contentStart <= pos {
			return ContextStyleBlock
		}
		// pos is inside the <style> opening tag's attributes — fall through to attribute handling
	}

	// Check if inside an HTML attribute
	if ctx, ok := classifyAttributeContext(body, lowerBody, pos, canary); ok {
		return ctx
	}

	// Default: HTML body context
	return ContextHTMLBody
}

// isInsideHTMLComment checks if the position is within <!-- ... -->
func isInsideHTMLComment(lowerBody string, pos int) bool {
	// Find the last comment open before pos
	lastOpen := strings.LastIndex(lowerBody[:pos], "<!--")
	if lastOpen == -1 {
		return false
	}
	// Check that there's no close between lastOpen and pos
	closeAfterOpen := strings.Index(lowerBody[lastOpen:pos], "-->")
	return closeAfterOpen == -1
}

// isInsideTag checks if the position falls between an opening and closing tag.
func isInsideTag(lowerBody string, pos int, tagName string) bool {
	openTag := "<" + tagName
	closeTag := "</" + tagName

	// Find the last opening tag before pos by scanning from the start
	lastOpen := -1
	idx := 0
	for {
		found := strings.Index(lowerBody[idx:pos], openTag)
		if found == -1 {
			break
		}
		absIdx := idx + found
		endIdx := absIdx + len(openTag)
		if endIdx < len(lowerBody) {
			ch := lowerBody[endIdx]
			if ch == ' ' || ch == '>' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '/' {
				lastOpen = absIdx
			}
		}
		idx = absIdx + 1
	}

	if lastOpen == -1 {
		return false
	}

	// Check there's no close tag between lastOpen and pos.
	// Like the open-tag scan, validate the boundary character after the match
	// so that e.g. "</scripting" doesn't falsely match "</script".
	searchIdx := lastOpen
	for {
		found := strings.Index(lowerBody[searchIdx:pos], closeTag)
		if found == -1 {
			break
		}
		absIdx := searchIdx + found
		endIdx := absIdx + len(closeTag)
		if endIdx >= len(lowerBody) {
			return false // close tag at end of body counts
		}
		ch := lowerBody[endIdx]
		if ch == ' ' || ch == '>' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '/' {
			return false // valid close tag found between open and pos
		}
		searchIdx = absIdx + 1
	}
	return true
}

// classifyScriptContext determines if the position is inside a <script> tag
// and what sub-context within the script.
func classifyScriptContext(body, lowerBody string, pos int, canary string) (ReflectionContext, bool) {
	if !isInsideTag(lowerBody, pos, "script") {
		return ContextNone, false
	}

	// Now determine the JS sub-context by examining chars before the canary
	// within the script block
	scriptStart := findLastTagContentStart(lowerBody, pos, "script")
	if scriptStart == -1 || scriptStart > pos {
		// scriptStart == -1: couldn't locate the tag content start
		// scriptStart > pos: canary is inside the opening tag's attributes,
		// not the script body — fall through to attribute handling.
		if scriptStart > pos {
			return ContextNone, false
		}
		return ContextScriptBlock, true
	}

	segment := body[scriptStart:pos]
	ctx := classifyJSContext(segment)
	return ctx, true
}

// findLastTagContentStart finds the position just after the closing > of the
// last opening tag before pos.
func findLastTagContentStart(lowerBody string, pos int, tagName string) int {
	openTag := "<" + tagName
	lastOpen := -1
	idx := 0
	for {
		found := strings.Index(lowerBody[idx:pos], openTag)
		if found == -1 {
			break
		}
		absIdx := idx + found
		endIdx := absIdx + len(openTag)
		// Validate boundary: next char must be >, whitespace, /, or end-of-string
		// to avoid matching e.g. <script-loader> as <script>.
		if endIdx >= len(lowerBody) {
			lastOpen = absIdx
		} else {
			ch := lowerBody[endIdx]
			if ch == ' ' || ch == '>' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '/' {
				lastOpen = absIdx
			}
		}
		idx = absIdx + 1
	}
	if lastOpen == -1 {
		return -1
	}
	// Find the closing > of this tag
	closeAngle := strings.IndexByte(lowerBody[lastOpen:], '>')
	if closeAngle == -1 {
		return -1
	}
	return lastOpen + closeAngle + 1
}

// classifyJSContext examines the JavaScript preceding the canary to determine
// if we're inside a string literal, template literal, or raw block.
func classifyJSContext(jsSegment string) ReflectionContext {
	inSingleQuote := false
	inDoubleQuote := false
	inTemplate := false
	escaped := false

	for i := 0; i < len(jsSegment); i++ {
		ch := jsSegment[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		switch {
		case inSingleQuote:
			if ch == '\'' {
				inSingleQuote = false
			}
		case inDoubleQuote:
			if ch == '"' {
				inDoubleQuote = false
			}
		case inTemplate:
			if ch == '`' {
				inTemplate = false
			}
		default:
			switch ch {
			case '\'':
				inSingleQuote = true
			case '"':
				inDoubleQuote = true
			case '`':
				inTemplate = true
			}
		}
	}

	switch {
	case inSingleQuote:
		return ContextScriptStringSingle
	case inDoubleQuote:
		return ContextScriptStringDouble
	case inTemplate:
		return ContextScriptTemplate
	default:
		return ContextScriptBlock
	}
}

// classifyAttributeContext determines if the position is inside an HTML attribute value.
// It uses heuristic scanning rather than the HTML tokenizer because the canary
// may contain characters (like < >) that break standard HTML parsing.
func classifyAttributeContext(body, lowerBody string, pos int, canary string) (ReflectionContext, bool) {
	// Find the last '<' before pos that starts a tag
	lastAngle := strings.LastIndexByte(lowerBody[:pos], '<')
	if lastAngle == -1 {
		return ContextNone, false
	}

	// Check if we're inside a tag (no unescaped > between lastAngle and pos
	// that would close the tag — but we only look at the portion before the
	// canary since the canary itself may contain >)
	segment := lowerBody[lastAngle:pos]

	// If there's a > before the canary, we may not be inside a tag.
	// However, we need to be careful: the > could be inside an attribute value.
	// Use quote tracking to determine this.
	inTag := isPositionInsideTag(segment)
	if !inTag {
		return ContextNone, false
	}

	// We're inside a tag. Find the attribute name by scanning backward from
	// the canary position to find the most recent attribute assignment (= followed by quote).
	attrName := findAttributeName(lowerBody[lastAngle:pos])
	if attrName == "" {
		return ContextNone, false
	}

	// Determine quote type
	quoteCtx := classifyAttrQuoteFromSegment(lowerBody[lastAngle:pos])

	// Check if it's a URL attribute
	if _, isURL := urlAttributes[attrName]; isURL {
		return ContextURLAttribute, true
	}

	return quoteCtx, true
}

// isPositionInsideTag determines if the segment (from '<' to canary position)
// represents an open tag by tracking quotes. A '>' outside quotes would close
// the tag, meaning we're not inside one.
func isPositionInsideTag(segment string) bool {
	inDouble := false
	inSingle := false
	for _, ch := range segment {
		switch {
		case ch == '"' && !inSingle:
			inDouble = !inDouble
		case ch == '\'' && !inDouble:
			inSingle = !inSingle
		case ch == '>' && !inDouble && !inSingle:
			// Tag closed before canary — we're not inside a tag
			return false
		}
	}
	// No unquoted > found — still inside the tag
	return true
}

// findAttributeName scans backward through the tag segment to find the
// attribute name whose value contains the canary.
func findAttributeName(tagSegment string) string {
	// Find the last '=' that precedes a quote character
	// Pattern: attrname = "... or attrname='...
	lastEq := strings.LastIndexByte(tagSegment, '=')
	if lastEq == -1 {
		return ""
	}

	// Check that after '=' there's a quote
	afterEq := strings.TrimLeft(tagSegment[lastEq+1:], " \t\n\r")
	if len(afterEq) == 0 {
		return ""
	}
	if afterEq[0] != '"' && afterEq[0] != '\'' {
		// Unquoted attribute — still try to find the name
	}

	// Scan backward from '=' to find the attribute name
	nameEnd := lastEq
	nameStart := nameEnd - 1
	// Skip whitespace before =
	for nameStart >= 0 && (tagSegment[nameStart] == ' ' || tagSegment[nameStart] == '\t' || tagSegment[nameStart] == '\n' || tagSegment[nameStart] == '\r') {
		nameStart--
	}
	if nameStart < 0 {
		return ""
	}
	nameEnd = nameStart + 1

	// Scan back through the attribute name
	for nameStart >= 0 {
		ch := tagSegment[nameStart]
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '"' || ch == '\'' || ch == '>' {
			break
		}
		nameStart--
	}
	nameStart++

	if nameStart >= nameEnd {
		return ""
	}
	return strings.ToLower(tagSegment[nameStart:nameEnd])
}

// classifyAttrQuoteFromSegment determines the quote type by finding the last
// unmatched quote character in the tag segment before the canary.
func classifyAttrQuoteFromSegment(segment string) ReflectionContext {
	// Find the last '=' and then the quote after it
	lastEq := strings.LastIndexByte(segment, '=')
	if lastEq == -1 {
		return ContextHTMLAttrUnquoted
	}

	afterEq := strings.TrimLeft(segment[lastEq+1:], " \t\n\r")
	if len(afterEq) == 0 {
		return ContextHTMLAttrUnquoted
	}

	switch afterEq[0] {
	case '"':
		return ContextHTMLAttrDoubleQuoted
	case '\'':
		return ContextHTMLAttrSingleQuoted
	default:
		return ContextHTMLAttrUnquoted
	}
}

// asciiToLower performs ASCII-only lowercasing. Unlike strings.ToLower, this
// preserves byte offsets for non-ASCII characters (e.g. Turkish İ) so that
// positions found in the lowered string can be used to index the original.
func asciiToLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		} else {
			b[i] = c
		}
	}
	return string(b)
}
