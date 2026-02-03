package xss

import (
	"strings"
)

// DetectContexts detects all reflection contexts where the canary appears in the response body.
// It performs case-insensitive search and analyzes each reflection position to determine:
//   - Context type (HTML body, attribute, script, etc.)
//   - Available characters (which special chars are not filtered)
//   - Position and surrounding text
//
// Returns up to 10 reflections. Empty slice if canary not found.
func DetectContexts(body, canary string) []ReflectionInfo {
	var reflections []ReflectionInfo

	// Guard against empty canary (would cause infinite loop)
	if canary == "" {
		return reflections
	}

	// Find all occurrences (case-insensitive)
	lowerBody := strings.ToLower(body)
	lowerCanary := strings.ToLower(canary)

	offset := 0
	for {
		pos := strings.Index(lowerBody[offset:], lowerCanary)
		if pos == -1 {
			break
		}

		actualPos := offset + pos
		reflection := analyzeContextAtPosition(body, actualPos, canary)
		reflections = append(reflections, reflection)

		offset = actualPos + len(canary)

		// Limit to 10 reflections to avoid performance issues
		if len(reflections) >= 10 {
			break
		}
	}

	return reflections
}

// analyzeContextAtPosition analyzes the context type and available characters at a specific
// position where the canary appears. It extracts surrounding text (up to 200 chars before,
// 200 chars after) and performs context detection and character filtering analysis.
func analyzeContextAtPosition(body string, canaryPos int, canary string) ReflectionInfo {
	canaryEnd := canaryPos + len(canary)

	// Bounds check to prevent panic
	if canaryEnd > len(body) {
		canaryEnd = len(body)
	}

	// Extract surrounding text (200 chars before/after)
	start := max(0, canaryPos-200)
	end := min(len(body), canaryEnd+200)

	beforeCanary := body[start:canaryPos]
	afterCanary := body[canaryEnd:end]

	// Detect context by walking backwards
	context := detectContextType(body, canaryPos)

	// Detect available characters
	chars := detectAvailableCharacters(body[canaryPos:canaryEnd], canary)

	// Extract metadata (quote char, attribute name, etc.)
	attributeName, quoteChar := extractAttributeMetadata(beforeCanary, context)

	return ReflectionInfo{
		Position:       canaryPos,
		Context:        context,
		AvailableChars: chars,
		BeforeCanary:   beforeCanary,
		AfterCanary:    afterCanary,
		AttributeName:  attributeName,
		QuoteChar:      quoteChar,
	}
}

// detectContextType determines the context type at the given position by analyzing
// preceding text. Uses a lookback approach to detect:
//   - HTML comments (<!-- -->)
//   - Script blocks (<script>) and script strings
//   - Style blocks (<style>)
//   - HTML attributes (quoted, unquoted, URL attributes)
//   - HTML body (default)
//
// Detection order ensures most specific contexts are checked first.
func detectContextType(body string, pos int) ContextType {
	// Walk backwards to find context markers
	lookback := body[max(0, pos-500):pos]
	lookbackLower := strings.ToLower(lookback) // Case-insensitive matching for tags

	// Check for script context (highest priority)
	if lastIndex := strings.LastIndex(lookbackLower, "<script"); lastIndex != -1 {
		afterScript := lookbackLower[lastIndex:]
		// Make sure we're inside the script tag, not after </script>
		if !strings.Contains(afterScript, "</script>") {
			// Check if the opening tag is properly closed with >
			// This handles cases like <script src="CANARY"> where we're in an attribute
			closingBracketPos := strings.Index(afterScript, ">")
			if closingBracketPos == -1 {
				// No closing bracket found, we're still in the opening tag attributes
				return ContextHTMLAttributeUnquoted
			}

			// We're inside the script content (after the opening tag's >)
			// Use the portion after the closing bracket for string context detection
			// Note: lastIndex and closingBracketPos are from lookbackLower, but since
			// strings.ToLower preserves byte positions, indexing into lookback is safe
			scriptContent := lookback[lastIndex+closingBracketPos+1:]
			if isInStringContext(scriptContent) {
				// Differentiate between string and template literal
				return detectStringType(scriptContent)
			}
			return ContextScriptBlock
		}
	}

	// Check for style context
	if lastIndex := strings.LastIndex(lookbackLower, "<style"); lastIndex != -1 {
		afterStyle := lookbackLower[lastIndex:]
		if !strings.Contains(afterStyle, "</style>") {
			// Check if the opening tag is properly closed with >
			closingBracketPos := strings.Index(afterStyle, ">")
			if closingBracketPos == -1 {
				// No closing bracket found, we're still in the opening tag attributes
				return ContextHTMLAttributeUnquoted
			}
			return ContextStyleBlock
		}
	}

	// Check for comment context
	commentStart := strings.LastIndex(lookbackLower, "<!--")
	commentEnd := strings.LastIndex(lookbackLower, "-->")
	if commentStart != -1 && (commentEnd == -1 || commentStart > commentEnd) {
		return ContextHTMLComment
	}

	// Check for attribute context
	if isInAttributeContext(lookback) {
		// Check if we're specifically in a URL attribute
		if isInURLAttribute(lookback) {
			return ContextURLAttribute
		}

		quoteChar := getAttributeQuoteChar(lookback)
		if quoteChar == "\"" || quoteChar == "'" {
			return ContextHTMLAttributeQuoted
		}
		return ContextHTMLAttributeUnquoted
	}

	// Default to HTML body
	return ContextHTMLBody
}

// countPrecedingBackslashes counts consecutive backslashes immediately before position i.
// Used to determine if a quote character is escaped in JavaScript string contexts.
// Returns the count of backslashes (0 if none found).
func countPrecedingBackslashes(text string, i int) int {
	count := 0
	for j := i - 1; j >= 0 && text[j] == '\\'; j-- {
		count++
	}
	return count
}

// isInStringContext detects if the position is inside a JavaScript string by counting
// unescaped quotes in the preceding text. Handles both single (') and double (") quotes,
// accounting for backslash escaping. Returns true if inside a string context.
func isInStringContext(text string) bool {
	// Count quotes to determine if we're inside a string
	// This is a simple heuristic - count unescaped quotes
	singleQuotes := 0
	doubleQuotes := 0
	backticks := 0

	for i := 0; i < len(text); i++ {
		// Quote is unescaped if preceded by even number of backslashes (0, 2, 4...)
		isEscaped := countPrecedingBackslashes(text, i)%2 == 1

		if text[i] == '\'' && !isEscaped {
			singleQuotes++
		}
		if text[i] == '"' && !isEscaped {
			doubleQuotes++
		}
		if text[i] == '`' {
			backticks++
		}
	}

	// Odd number of quotes or backticks means we're inside a string/template literal
	return (singleQuotes%2 == 1) || (doubleQuotes%2 == 1) || (backticks%2 == 1)
}

// detectStringType determines the specific string context type by analyzing quote patterns.
// Differentiates between:
//   - Template literals (backticks)
//   - Single-quoted strings
//   - Double-quoted strings
//
// Returns ContextScriptString for quoted strings, or ContextScriptTemplateLiteral for backticks.
func detectStringType(text string) ContextType {
	// Determine the type of string context (regular string vs template literal)
	backticks := 0
	singleQuotes := 0
	doubleQuotes := 0

	for i := 0; i < len(text); i++ {
		// Quote is unescaped if preceded by even number of backslashes (0, 2, 4...)
		isEscaped := countPrecedingBackslashes(text, i)%2 == 1

		if text[i] == '`' {
			backticks++
		}
		if text[i] == '\'' && !isEscaped {
			singleQuotes++
		}
		if text[i] == '"' && !isEscaped {
			doubleQuotes++
		}
	}

	// Check what type of string we're in based on odd counts
	if backticks%2 == 1 {
		return ContextScriptTemplateLiteral
	}

	return ContextScriptString
}

// isInAttributeContext detects if the position is inside an HTML attribute by looking
// for the pattern: opening tag + attribute name + equals sign. Uses regex pattern
// matching on the preceding text. Returns true if in attribute context.
func isInAttributeContext(text string) bool {
	// Look for pattern: <tag attr=
	lastOpenTag := strings.LastIndex(text, "<")
	lastCloseTag := strings.LastIndex(text, ">")
	lastEquals := strings.LastIndex(text, "=")

	// We're in an attribute if: < comes before = and no > after =
	return lastOpenTag != -1 && lastEquals != -1 &&
		lastOpenTag < lastEquals && lastCloseTag < lastEquals
}

// isInURLAttribute checks if the position is in a URL-bearing attribute such as
// href, src, action, data, formaction, or poster. These attributes have special
// XSS exploitation considerations (e.g., javascript: protocol). Returns true
// if inside a URL attribute context.
func isInURLAttribute(text string) bool {
	// List of URL attributes (comprehensive list for XSS detection)
	urlAttributes := []string{
		"href", "src", "action", "data", "formaction", "poster",
		"codebase", "cite", "background", "dynsrc", "lowsrc", "manifest",
	}

	textLower := strings.ToLower(text)

	// Find the last attribute assignment
	lastEquals := strings.LastIndex(text, "=")
	if lastEquals == -1 {
		return false
	}

	// Look backwards from = to find attribute name
	// Get text before equals and extract last word
	beforeEquals := strings.TrimSpace(textLower[:lastEquals])

	// Extract the last word (attribute name)
	words := strings.Fields(beforeEquals)
	if len(words) == 0 {
		return false
	}

	attrName := words[len(words)-1]

	// Check if it's a URL attribute
	for _, urlAttr := range urlAttributes {
		if attrName == urlAttr {
			return true
		}
	}

	return false
}

// getAttributeQuoteChar determines the quote character used for the current attribute.
// Returns:
//   - "\"" for double-quoted attributes
//   - "'" for single-quoted attributes
//   - "" (empty string) for unquoted attributes
func getAttributeQuoteChar(text string) string {
	// Find the last = and check what comes after
	lastEquals := strings.LastIndex(text, "=")
	if lastEquals == -1 || lastEquals == len(text)-1 {
		return ""
	}

	afterEquals := text[lastEquals+1:]
	afterEquals = strings.TrimLeft(afterEquals, " \t\n\r")

	if len(afterEquals) > 0 {
		if afterEquals[0] == '"' {
			return "\""
		}
		if afterEquals[0] == '\'' {
			return "'"
		}
	}

	return "" // Unquoted
}

// extractAttributeMetadata extracts attribute name and quote character from the text
// preceding the canary position. Uses pattern matching to find the attribute assignment
// pattern. Returns attribute name and quote char (or empty strings if not found).
// Context parameter helps optimize the extraction for attribute contexts.
func extractAttributeMetadata(beforeCanary string, context ContextType) (string, string) {
	if context != ContextHTMLAttributeQuoted &&
		context != ContextHTMLAttributeUnquoted &&
		context != ContextURLAttribute {
		return "", ""
	}

	// Extract attribute name (word before =)
	parts := strings.Split(beforeCanary, "=")
	if len(parts) < 2 {
		return "", ""
	}

	attrPart := strings.TrimSpace(parts[len(parts)-2])
	words := strings.Fields(attrPart)
	if len(words) > 0 {
		attrName := words[len(words)-1]
		quoteChar := getAttributeQuoteChar(beforeCanary)
		return attrName, quoteChar
	}

	return "", ""
}

// detectAvailableCharacters determines which special characters survived server-side encoding.
//
// Detection Logic:
//   - If a character WAS in the original canary: available only if it appears in reflected version
//   - If a character was NOT in the original canary: assumed available (optimistic approach)
//
// The optimistic approach is intentional - when we can't determine if a character is filtered,
// we allow payload testing to proceed. The verification phase will catch false positives
// by checking if the payload actually executes in an exploitable context.
//
// Example with DefaultCanary "xSs9K7j<>'\"/()":
//   - Original: xSs9K7j<>'"/()
//   - Reflected: xSs9K7j&lt;&gt;'"/()
//   - Result: LessThan=false, GreaterThan=false, SingleQuote=true, DoubleQuote=true
func detectAvailableCharacters(reflectedCanary, originalCanary string) CharacterSet {
	return CharacterSet{
		LessThan:    !strings.Contains(originalCanary, "<") || strings.Contains(reflectedCanary, "<"),
		GreaterThan: !strings.Contains(originalCanary, ">") || strings.Contains(reflectedCanary, ">"),
		SingleQuote: !strings.Contains(originalCanary, "'") || strings.Contains(reflectedCanary, "'"),
		DoubleQuote: !strings.Contains(originalCanary, "\"") || strings.Contains(reflectedCanary, "\""),
		Slash:       !strings.Contains(originalCanary, "/") || strings.Contains(reflectedCanary, "/"),
		Backtick:    !strings.Contains(originalCanary, "`") || strings.Contains(reflectedCanary, "`"),
	}
}
