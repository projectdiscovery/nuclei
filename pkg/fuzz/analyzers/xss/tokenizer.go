package xss

import (
	"sort"
	"strings"

	"golang.org/x/net/html"
)

// DetectContextsRobust tokenizes the HTML response to find all places where our probe appears
// For each one, it figures out the context (like "inside a script tag" or "in an attribute")
func DetectContextsRobust(body string, smartCanary string) []ReflectionContext {
	contexts := []ReflectionContext{}

	// Extract base canary for position finding
	baseCanary := extractBaseCanary(smartCanary)

	// Find all canary positions using base canary
	// We use baseCanary (not smartCanary) because special chars might be partially encoded
	// Example: "xSs9K7j&lt;&gt;'" has encoded < and > but unencoded '
	// This is still exploitable via the quote, so we must detect it
	canaryPositions := findAllOccurrences(body, baseCanary)
	if len(canaryPositions) == 0 {
		return contexts
	}

	// Track which positions have been processed by the tokenizer
	processedPos := make(map[int]struct{})

	// Tokenize HTML and track state
	tokenizer := html.NewTokenizer(strings.NewReader(body))
	position := 0
	inScript := false
	inStyle := false
	inRCDATA := false // <textarea> and <title> need special handling
	var currentTag string
	scriptType := ""

	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			break
		}

		tokenRaw := tokenizer.Raw()
		tokenStart := position
		// Note: len(tokenRaw) is safe to use after subsequent Token() calls because
		// len() reads from the slice header, not the underlying array which may be overwritten.
		lastTokenRawLen := len(tokenRaw)
		position += lastTokenRawLen
		token := tokenizer.Token()

		// Check if any canary is in this token
		for _, canaryPos := range canaryPositions {
			if canaryPos >= tokenStart && canaryPos < position {
				processedPos[canaryPos] = struct{}{}
				contextType := detectContextFromToken(token, tokenType, canaryPos-tokenStart, inScript, inStyle, inRCDATA, currentTag, scriptType, baseCanary)

				// Analyze which characters survived to detect active filters
				filterInfo := detectFilters(body, canaryPos, smartCanary)

				reflectionCtx := ReflectionContext{
					Type:         contextType,
					Location:     canaryPos,
					TagName:      currentTag,
					FilterBypass: filterInfo,
				}

				// Detect quote character for attribute contexts and refine context type
				if isAttributeContext(contextType) {
					quoteChar := detectQuoteChar(body, canaryPos)
					reflectionCtx.QuoteChar = quoteChar

					// Refine context type based on actual quote character
					if quoteChar == '\'' {
						reflectionCtx.Type = ContextHTMLAttrSingleQuoted
					} else if quoteChar == '"' {
						reflectionCtx.Type = ContextHTMLAttrDoubleQuoted
					} else {
						reflectionCtx.Type = ContextHTMLAttrUnquoted
					}
				}

				// Optimization: Only include exploitable contexts
				// Unquoted attributes are always considered exploitable (can inject handlers via space)
				if !reflectionCtx.FilterBypass.IsExploitable && reflectionCtx.Type != ContextHTMLAttrUnquoted {
					continue
				}
				contexts = append(contexts, reflectionCtx)
			}
		}

		// Update state machine
		if tokenType == html.StartTagToken || tokenType == html.SelfClosingTagToken {
			currentTag = token.Data

			if token.Data == "script" {
				inScript = true
				// Check script type attribute
				scriptType = ""
				for _, attr := range token.Attr {
					if attr.Key == "type" {
						scriptType = strings.ToLower(attr.Val)
						break
					}
				}
			} else if token.Data == "style" {
				inStyle = true
			} else if token.Data == "textarea" || token.Data == "title" {
				inRCDATA = true
			}
		} else if tokenType == html.EndTagToken {
			if token.Data == currentTag {
				currentTag = ""
			}
			if token.Data == "script" {
				inScript = false
				scriptType = ""
			} else if token.Data == "style" {
				inStyle = false
			} else if token.Data == "textarea" || token.Data == "title" {
				inRCDATA = false
			}
		}
	}


	// Drain any canaries that were missed if the tokenizer stopped early due to malformed HTML or EOF
	for _, canaryPos := range canaryPositions {
		if _, exists := processedPos[canaryPos]; !exists {
			// If we missed it, treat it as plain HTML text (safest fallback)
			filterInfo := detectFilters(body, canaryPos, smartCanary)
			if !filterInfo.IsExploitable {
				continue
			}
			contexts = append(contexts, ReflectionContext{
				Type:         ContextHTMLText,
				Location:     canaryPos,
				FilterBypass: filterInfo,
			})
		}
	}

	// Sort contexts by exploitability (easiest first)
	// This ensures that even the fallback contexts (which represent malformed HTML) are correctly prioritized
	sort.Slice(contexts, func(i, j int) bool {
		return contexts[i].Type.ExploitabilityRank() < contexts[j].Type.ExploitabilityRank()
	})

	return contexts
}

// extractBaseCanary extracts the base canary without special characters
func extractBaseCanary(smartCanary string) string {
	// Smart canary format: "Nucl3iXXXXXX<>'\""
	// We need to extract "Nucl3iXXXXXX"
	// Find the position of the first special char
	for i, char := range smartCanary {
		if char == '<' || char == '>' || char == '\'' || char == '"' {
			return smartCanary[:i]
		}
	}
	return smartCanary
}

// findAllOccurrences finds all positions where the canary appears in the body
func findAllOccurrences(body, canary string) []int {
	var positions []int
	start := 0
	for {
		idx := strings.Index(body[start:], canary)
		if idx == -1 {
			break
		}
		actualIdx := start + idx
		positions = append(positions, actualIdx)
		start = actualIdx + 1 // Move past this occurrence
	}
	return positions
}

// detectContextFromToken determines the context type based on the HTML token
func detectContextFromToken(token html.Token, tokenType html.TokenType, offsetInToken int, inScript, inStyle, inRCDATA bool, currentTag string, scriptType string, baseCanary string) ContextType {
	switch tokenType {
	case html.TextToken:
		if inScript {
			// Check for JSON context within script tags
			if scriptType == "application/json" || scriptType == "text/json" {
				return ContextScriptJSON
			}
			return analyzeJSContext(string(token.Data), offsetInToken)
		}
		if inStyle {
			return ContextStyleProperty
		}
		if inRCDATA {
			return ContextRCDATA
		}
		return ContextHTMLText

	case html.StartTagToken, html.SelfClosingTagToken:
		// Check if canary is in an attribute value or name
		for _, attr := range token.Attr {
			if strings.Contains(attr.Val, baseCanary) {
				// Check for event handler attributes
				if strings.HasPrefix(strings.ToLower(attr.Key), "on") {
					return ContextEventHandler
				}
				// The html.Tokenizer doesn't preserve quote information
				// We need to determine it from the attribute value context
				// Unquoted attributes have no spaces and end at whitespace or >
				// For now, we'll default to double-quoted and let detectQuoteChar refine it
				return ContextHTMLAttrDoubleQuoted
			}
			// Also check attribute name
			if strings.Contains(attr.Key, baseCanary) {
				return ContextHTMLAttrUnquoted
			}
		}
		return ContextHTMLText

	case html.CommentToken:
		return ContextHTMLComment

	default:
		return ContextUnknown
	}
}

// analyzeJSContext analyzes JavaScript context to determine if we're in a string or code
func analyzeJSContext(jsCode string, offset int) ContextType {
	// Look backward from offset to determine context
	if offset > len(jsCode) {
		offset = len(jsCode)
	}

	beforeCanary := jsCode[:offset]

	// Iterate through the code to track state
	var (
		inSingleQuote bool
		inDoubleQuote bool
		inBacktick    bool
		isEscaped     bool
	)

	for _, r := range beforeCanary {
		if isEscaped {
			isEscaped = false
			continue
		}

		if r == '\\' {
			isEscaped = true
			continue
		}

		// Toggle state based on quotes, but only if we're not inside another quote type
		switch r {
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

	if inBacktick {
		return ContextScriptTemplateString
	}
	if inSingleQuote {
		return ContextScriptStringSingle
	}
	if inDoubleQuote {
		return ContextScriptStringDouble
	}

	return ContextScriptCode
}

// detectQuoteChar detects the quote character used in an attribute
// It properly handles nested quotes (polyglots) by finding the OPENING quote
func detectQuoteChar(body string, canaryPos int) rune {
	// Look backward to find the attribute start
	// Use 1000 chars to handle complex/long attributes
	searchStart := canaryPos - 1000
	if searchStart < 0 {
		searchStart = 0
	}
	snippet := body[searchStart:canaryPos]

	// Iterate to find the first quote that opens an attribute and doesn't close
	for i := 0; i < len(snippet); i++ {
		char := snippet[i]
		if char == '"' || char == '\'' {
			// Check if this quote is an attribute starter (preceded by =)
			isAttrStart := false
			// Scan backwards from quote ignoring space
			for j := i - 1; j >= 0; j-- {
				c := snippet[j]
				if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
					continue
				}
				if c == '=' {
					isAttrStart = true
				}
				break
			}

			if isAttrStart {
				// This is an attribute opening quote.
				// Check if it closes before the canary
				closingPos := strings.Index(snippet[i+1:], string(char))

				if closingPos == -1 {
					// No closing quote found -> Encloses canary -> Winner!
					return rune(char)
				}

				// It closes. Skip past it.
				i += closingPos + 1
			}
		}
	}

	return 0 // Unquoted
}

// detectFilters checks which special characters survived in the reflection
// This determines what filter bypasses are possible and overall exploitability
func detectFilters(body string, canaryPos int, smartCanary string) FilterBypassInfo {
	var (
		angleBracketsAllowed bool
		singleQuoteAllowed   bool
		doubleQuoteAllowed   bool
	)

	// Find the reflected region - limit search to avoid picking up HTML structure
	// Buffer accounts for HTML entity encoding (e.g., &lt; is 4 chars vs < is 1)
	maxEntityExpansion := 6 * 4 // 6 special chars * ~4 chars per entity
	searchEnd := canaryPos + len(smartCanary) + maxEntityExpansion
	if searchEnd > len(body) {
		searchEnd = len(body)
	}

	snippet := body[canaryPos:searchEnd]

	// Try to limit snippet to avoid HTML structure after the canary
	// Look for the end of the base canary content
	baseCanary := extractBaseCanary(smartCanary)
	idx := strings.Index(snippet, baseCanary)
	if idx != -1 {
		// Analyze text AFTER the base canary
		postCanary := snippet[idx+len(baseCanary):]

		// 1. Check Angle Brackets (< and >)
		// Both must be unencoded to be useful for tag injection
		angleBracketsAllowed = isAllowed(postCanary, "<", "&lt;") && isAllowed(postCanary, ">", "&gt;")

		// 2. Check Single Quote (')
		singleQuoteAllowed = isAllowed(postCanary, "'", "&#39;", "&apos;", "&#x27;")

		// 3. Check Double Quote (")
		doubleQuoteAllowed = isAllowed(postCanary, "\"", "&quot;", "&#34;", "&#x22;")
	} else {
		// Fallback if base canary not found (unlikely)
		// Use original logic but with strict checks (first occurrence wins)

		// 1. Check Angle Brackets (< and >)
		angleBracketsAllowed = isAllowed(snippet, "<", "&lt;")

		// 2. Check Single Quote (')
		singleQuoteAllowed = isAllowed(snippet, "'", "&#39;", "&apos;", "&#x27;")

		// 3. Check Double Quote (")
		doubleQuoteAllowed = isAllowed(snippet, "\"", "&quot;", "&#34;", "&#x22;")
	}

	// Determine blocked characters
	blockedChars := ""
	if !angleBracketsAllowed {
		blockedChars += "<>"
	}
	if !singleQuoteAllowed {
		blockedChars += "'"
	}
	if !doubleQuoteAllowed {
		blockedChars += "\""
	}

	// A context is exploitable if at least some XSS-critical chars are allowed
	// For HTML contexts, we need angle brackets
	// For attribute contexts, we need quotes
	// For script contexts, we need quotes and semicolons
	isExploitable := angleBracketsAllowed || singleQuoteAllowed || doubleQuoteAllowed

	return FilterBypassInfo{
		AngleBracketsAllowed: angleBracketsAllowed,
		SingleQuoteAllowed:   singleQuoteAllowed,
		DoubleQuoteAllowed:   doubleQuoteAllowed,
		IsExploitable:        isExploitable,
		BlockedChars:         blockedChars,
	}
}

// isAttributeContext checks if a context type is an attribute context
func isAttributeContext(ctx ContextType) bool {
	return ctx == ContextHTMLAttrDoubleQuoted ||
		ctx == ContextHTMLAttrSingleQuoted ||
		ctx == ContextHTMLAttrUnquoted
}

// isAllowed checks if a literal character allowed (appears before any encoded variant)
func isAllowed(text, literal string, entities ...string) bool {
	idxLit := strings.Index(text, literal)
	if idxLit == -1 {
		return false
	}
	// Check if any entity appears BEFORE the literal
	for _, entity := range entities {
		idxEnc := strings.Index(text, entity)
		if idxEnc != -1 && idxEnc < idxLit {
			return false
		}
	}
	return true
}
