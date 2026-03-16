package xss

import (
	"fmt"
	"strings"
)

// maxReflections limits the number of reflections processed per response
// to prevent memory exhaustion from adversarial inputs.
const maxReflections = 50

// Context represents the HTML context where a reflection was found
type Context int

const (
	ContextHTMLBody Context = iota
	ContextHTMLAttrDoubleQuoted
	ContextHTMLAttrSingleQuoted
	ContextHTMLAttrUnquoted
	ContextScriptBlock
	ContextScriptStringDouble
	ContextScriptStringSingle
	ContextScriptTemplateLiteral
	ContextHTMLComment
	ContextStyleBlock
	ContextURLAttribute
)

var contextNames = map[Context]string{
	ContextHTMLBody:              "html-body",
	ContextHTMLAttrDoubleQuoted:  "html-attr-double-quoted",
	ContextHTMLAttrSingleQuoted:  "html-attr-single-quoted",
	ContextHTMLAttrUnquoted:      "html-attr-unquoted",
	ContextScriptBlock:           "script-block",
	ContextScriptStringDouble:    "script-string-double",
	ContextScriptStringSingle:    "script-string-single",
	ContextScriptTemplateLiteral: "script-template",
	ContextHTMLComment:           "html-comment",
	ContextStyleBlock:            "style-block",
	ContextURLAttribute:          "url-attribute",
}

func (c Context) String() string {
	if name, ok := contextNames[c]; ok {
		return name
	}
	return "unknown"
}

// contextSeverity ranks contexts by exploitability (higher = more dangerous)
var contextSeverity = map[Context]int{
	ContextHTMLBody:              5,
	ContextHTMLAttrDoubleQuoted:  6,
	ContextHTMLAttrSingleQuoted:  6,
	ContextHTMLAttrUnquoted:      7,
	ContextScriptBlock:           9,
	ContextScriptStringDouble:    8,
	ContextScriptStringSingle:    8,
	ContextScriptTemplateLiteral: 8,
	ContextHTMLComment:           3,
	ContextStyleBlock:            4,
	ContextURLAttribute:          7,
}

// Reflection represents a single reflected payload finding
type Reflection struct {
	Context      Context
	Exploitable  bool
	BreakoutChar string
}

// classifyReflections finds all occurrences of the canary in body and
// classifies each one's HTML context. Uses heuristic quote-tracking rather
// than html.Tokenizer because the canary itself contains HTML-breaking
// characters (<>'") that would cause a tokenizer to misparse the document.
func classifyReflections(body, canary string) []Reflection {
	if canary == "" || body == "" {
		return nil
	}

	canaryLen := len(canary)
	var findings []Reflection
	offset := 0
	for offset+canaryLen <= len(body) {
		if len(findings) >= maxReflections {
			break
		}
		idx := indexFold(body[offset:], canary)
		if idx < 0 {
			break
		}
		absIdx := offset + idx
		before := body[:absIdx]
		ctx := classifyContext(before)
		exploitable, breakoutChar := isExploitable(ctx, body, absIdx, canary)
		findings = append(findings, Reflection{
			Context:      ctx,
			Exploitable:  exploitable,
			BreakoutChar: breakoutChar,
		})
		offset = absIdx + canaryLen
	}
	return findings
}

// indexFold finds the first case-insensitive occurrence of needle in haystack,
// returning the byte index in haystack. Uses EqualFold window scanning to
// avoid byte-length shifts that strings.ToLower can introduce for non-ASCII.
func indexFold(haystack, needle string) int {
	n := len(needle)
	if n == 0 {
		return 0
	}
	if n > len(haystack) {
		return -1
	}
	for i := 0; i <= len(haystack)-n; i++ {
		if strings.EqualFold(haystack[i:i+n], needle) {
			return i
		}
	}
	return -1
}

// classifyContext determines the HTML context based on content before the
// reflection point using heuristic analysis.
func classifyContext(before string) Context {
	lowerBefore := strings.ToLower(before)

	// Check comment context: <!-- without closing -->
	lastCommentOpen := strings.LastIndex(lowerBefore, "<!--")
	lastCommentClose := strings.LastIndex(lowerBefore, "-->")
	if lastCommentOpen > lastCommentClose {
		return ContextHTMLComment
	}

	// Check style context
	lastStyleOpen := strings.LastIndex(lowerBefore, "<style")
	lastStyleClose := strings.LastIndex(lowerBefore, "</style")
	if lastStyleOpen > lastStyleClose && lastStyleOpen > strings.LastIndex(lowerBefore, ">") {
		// Still inside the <style> opening tag
	} else if lastStyleOpen > lastStyleClose {
		return ContextStyleBlock
	}

	// Check script context
	lastScriptOpen := strings.LastIndex(lowerBefore, "<script")
	lastScriptClose := strings.LastIndex(lowerBefore, "</script")
	if lastScriptOpen > lastScriptClose {
		return classifyScriptContext(before[lastScriptOpen:])
	}

	// Check if inside an HTML tag (attribute context)
	lastLt := strings.LastIndex(before, "<")
	lastGt := strings.LastIndex(before, ">")
	if lastLt > lastGt {
		return classifyAttributeContext(before[lastLt:])
	}

	return ContextHTMLBody
}

// classifyScriptContext determines the specific JS context within a <script> block
func classifyScriptContext(scriptContent string) Context {
	// Find the end of the <script> opening tag
	gtIdx := strings.Index(scriptContent, ">")
	if gtIdx < 0 {
		// Still in the <script> opening tag attributes
		return classifyAttributeContext(scriptContent)
	}
	jsContent := scriptContent[gtIdx+1:]

	// Track quote state to determine JS string context
	inDouble := false
	inSingle := false
	inTemplate := false
	escaped := false

	for _, ch := range jsContent {
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}

		switch {
		case !inDouble && !inSingle && !inTemplate && ch == '"':
			inDouble = true
		case inDouble && ch == '"':
			inDouble = false
		case !inDouble && !inSingle && !inTemplate && ch == '\'':
			inSingle = true
		case inSingle && ch == '\'':
			inSingle = false
		case !inDouble && !inSingle && !inTemplate && ch == '`':
			inTemplate = true
		case inTemplate && ch == '`':
			inTemplate = false
		}
	}

	if inDouble {
		return ContextScriptStringDouble
	}
	if inSingle {
		return ContextScriptStringSingle
	}
	if inTemplate {
		return ContextScriptTemplateLiteral
	}
	return ContextScriptBlock
}

// classifyAttributeContext determines the attribute quote context
func classifyAttributeContext(tagContent string) Context {
	// Determine quote context by tracking quotes after the last '='
	lastEq := strings.LastIndex(tagContent, "=")
	if lastEq < 0 {
		return ContextHTMLAttrUnquoted
	}

	// Check if the attribute containing the reflection is a URL attribute
	// by parsing backwards from the '=' to find the attribute name.
	if isURLAttribute(tagContent, lastEq) {
		return ContextURLAttribute
	}

	afterEq := strings.TrimLeft(tagContent[lastEq+1:], " \t\n\r")
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

// isURLAttribute checks whether the attribute at the given '=' position
// is a URL-type attribute (href, src, action, formaction, data, poster).
func isURLAttribute(tagContent string, eqIdx int) bool {
	// Walk backwards from eqIdx to find the attribute name start
	nameEnd := eqIdx
	nameStart := nameEnd
	for nameStart > 0 && tagContent[nameStart-1] != ' ' && tagContent[nameStart-1] != '\t' &&
		tagContent[nameStart-1] != '\n' && tagContent[nameStart-1] != '\r' &&
		tagContent[nameStart-1] != '<' {
		nameStart--
	}
	attrName := strings.ToLower(tagContent[nameStart:nameEnd])
	urlAttrs := []string{"href", "src", "action", "formaction", "data", "poster"}
	for _, ua := range urlAttrs {
		if attrName == ua {
			return true
		}
	}
	return false
}

// isExploitable checks whether the context-specific breakout characters survived encoding
func isExploitable(ctx Context, body string, reflectionIdx int, canary string) (bool, string) {
	reflected := body[reflectionIdx : reflectionIdx+len(canary)]

	switch ctx {
	case ContextHTMLBody:
		if strings.Contains(reflected, "<") && strings.Contains(reflected, ">") {
			return true, "<>"
		}
	case ContextHTMLAttrDoubleQuoted:
		if strings.Contains(reflected, "\"") {
			return true, "\""
		}
	case ContextHTMLAttrSingleQuoted:
		if strings.Contains(reflected, "'") {
			return true, "'"
		}
	case ContextHTMLAttrUnquoted:
		if strings.Contains(reflected, ">") || strings.Contains(reflected, " ") {
			return true, "> or space"
		}
	case ContextScriptBlock:
		if strings.Contains(reflected, "<") || strings.Contains(reflected, "'") || strings.Contains(reflected, "\"") {
			return true, "</script> or quotes"
		}
	case ContextScriptStringDouble:
		if strings.Contains(reflected, "\"") {
			return true, "\""
		}
	case ContextScriptStringSingle:
		if strings.Contains(reflected, "'") {
			return true, "'"
		}
	case ContextScriptTemplateLiteral:
		if strings.Contains(reflected, "`") {
			return true, "`"
		}
	case ContextHTMLComment:
		if strings.Contains(reflected, ">") && strings.Contains(reflected, "-") {
			return true, "-->"
		}
	case ContextStyleBlock:
		if strings.Contains(reflected, "<") {
			return true, "</style>"
		}
	case ContextURLAttribute:
		// Only exploitable if the reflected value contains an unencoded colon,
		// which is required for javascript: protocol injection.
		if strings.Contains(reflected, ":") {
			return true, "javascript:"
		}
	}

	return false, ""
}

// formatFindings formats the reflection findings into a human-readable string
func formatFindings(findings []Reflection) string {
	if len(findings) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[xss_context] found %d reflection(s):", len(findings)))
	for i, f := range findings {
		exploitability := "not exploitable"
		if f.Exploitable {
			exploitability = fmt.Sprintf("exploitable (breakout: %s)", f.BreakoutChar)
		}
		sb.WriteString(fmt.Sprintf("\n  %d. context: %s, %s", i+1, f.Context, exploitability))
	}
	return sb.String()
}
