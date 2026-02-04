package xss

import (
	"sort"
	"strings"

	"golang.org/x/net/html"
)

// DetectContextsRobust uses HTML tokenizer for accurate context detection
// Also detects active filters and ranks contexts by exploitability
func DetectContextsRobust(body string, smartCanary string) []ReflectionContext {
	contexts := []ReflectionContext{}

	// Extract the base canary (without special chars)
	baseCanary := extractBaseCanary(smartCanary)

	// Find all canary positions
	canaryPositions := findAllOccurrences(body, baseCanary)
	if len(canaryPositions) == 0 {
		return contexts
	}

	// Tokenize HTML and track state
	tokenizer := html.NewTokenizer(strings.NewReader(body))
	position := 0
	inScript := false
	inStyle := false
	inRCDATA := false // Track textarea/title
	var currentTag string
	inSVG := false
	inMathML := false
	scriptType := ""

	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			break
		}

		token := tokenizer.Token()
		tokenStart := position
		tokenRaw := tokenizer.Raw()
		position += len(tokenRaw)

		// Check if any canary is in this token
		for _, canaryPos := range canaryPositions {
			if canaryPos >= tokenStart && canaryPos < position {
				contextType := detectContextFromToken(token, tokenType, canaryPos-tokenStart, inScript, inStyle, inRCDATA, currentTag, inSVG, inMathML, scriptType)

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

			// Track namespace changes (SVG/MathML)
			if token.Data == "svg" {
				inSVG = true
			} else if token.Data == "math" {
				inMathML = true
			}

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
			if token.Data == "script" {
				inScript = false
				scriptType = ""
			} else if token.Data == "style" {
				inStyle = false
			} else if token.Data == "svg" {
				inSVG = false
			} else if token.Data == "math" {
				inMathML = false
			} else if token.Data == "textarea" || token.Data == "title" {
				inRCDATA = false
			}
		}
	}

	// Sort contexts by exploitability (easiest first)
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
func detectContextFromToken(token html.Token, tokenType html.TokenType, offsetInToken int, inScript, inStyle, inRCDATA bool, currentTag string, inSVG, inMathML bool, scriptType string) ContextType {
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
		// Check if canary is in an attribute
		for _, attr := range token.Attr {
			if strings.Contains(attr.Val, extractBaseCanary(attr.Val)) {
				// The html.Tokenizer doesn't preserve quote information
				// We need to determine it from the attribute value context
				// Unquoted attributes have no spaces and end at whitespace or >
				// For now, we'll default to double-quoted and let detectQuoteChar refine it
				return ContextHTMLAttrDoubleQuoted
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

	// Count quotes to determine if we're in a string
	singleQuotes := strings.Count(beforeCanary, "'")
	doubleQuotes := strings.Count(beforeCanary, "\"")
	backticks := strings.Count(beforeCanary, "`")

	// Check for template strings
	if backticks%2 == 1 {
		return ContextScriptTemplateString
	}

	// Check for single-quoted strings
	if singleQuotes%2 == 1 {
		return ContextScriptStringSingle
	}

	// Check for double-quoted strings
	if doubleQuotes%2 == 1 {
		return ContextScriptStringDouble
	}

	// Not in a string, must be in code
	return ContextScriptCode
}

// detectAttributeQuoteContext detects the quote style of an attribute
// NOTE: The html.Tokenizer doesn't preserve quote info, so we rely on
// detectQuoteChar to refine this later using the body context
func detectAttributeQuoteContext(attrValue string) ContextType {
	// Default to double-quoted - will be refined by detectQuoteChar
	return ContextHTMLAttrDoubleQuoted
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
	// Find the reflected region - search for a larger snippet around the canary
	// to account for HTML encoding which can change the length
	searchEnd := canaryPos + len(smartCanary) + 50 // Extra buffer for HTML entities
	if searchEnd > len(body) {
		searchEnd = len(body)
	}

	// Get snippet that should contain the reflection
	snippet := body[canaryPos:searchEnd]

	// CRITICAL FIX: Check for RAW characters, not HTML entities
	// A character is "allowed" only if it appears in its literal form, not encoded

	// Check < and > - must appear as literal chars, not &lt; or &gt;
	hasLiteralLessThan := strings.Contains(snippet, "<")
	hasEncodedLessThan := strings.Contains(snippet, "&lt;")
	angleBracketsAllowed := hasLiteralLessThan && !hasEncodedLessThan && strings.Contains(snippet, ">") && !strings.Contains(snippet, "&gt;")

	// Check ' - must appear as literal, not &#39; or &apos;
	hasLiteralSingleQuote := strings.Contains(snippet, "'")
	hasEncodedSingleQuote := strings.Contains(snippet, "&#39;") || strings.Contains(snippet, "&apos;") || strings.Contains(snippet, "&#x27;")
	singleQuoteAllowed := hasLiteralSingleQuote && !hasEncodedSingleQuote

	// Check " - must appear as literal, not &quot;
	hasLiteralDoubleQuote := strings.Contains(snippet, "\"")
	hasEncodedDoubleQuote := strings.Contains(snippet, "&quot;") || strings.Contains(snippet, "&#34;") || strings.Contains(snippet, "&#x22;")
	doubleQuoteAllowed := hasLiteralDoubleQuote && !hasEncodedDoubleQuote

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
