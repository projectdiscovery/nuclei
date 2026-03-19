package xss

import (
	"regexp"
	"strings"
)

// ContextType represents the context in which a payload is reflected
type ContextType int

const (
	// ContextHTML is for reflection in HTML content (default/unclassified)
	ContextHTML ContextType = iota
	// ContextAttribute is for reflection in HTML attributes
	ContextAttribute
	// ContextScript is for reflection in JavaScript executable context
	ContextScript
	// ContextJSON is for reflection in JSON data (not executable)
	ContextJSON
	// ContextHTMLInjection is for reflection in contexts allowing HTML injection (like srcdoc)
	ContextHTMLInjection
)

var (
	// Patterns to detect different contexts
	scriptTypeJSONRegex = regexp.MustCompile(`(?i)<script[^>]*type\s*=\s*["']?application/json["']?[^>]*>`)
	scriptOpeningRegex  = regexp.MustCompile(`(?i)<script[^>]*>`)
	scriptClosingRegex  = regexp.MustCompile(`(?i)</script>`)
	// javaScriptURIRegex is kept for potential future use but not currently used
	// javaScriptURIRegex = regexp.MustCompile(`(?i)javascript\s*:`)
)

// ClassifyContext determines the context in which a payload appears in the response
// FIX: Now analyzes ALL occurrences of the payload, not just the first one
func ClassifyContext(htmlContent, payload string) ContextType {
	// Normalize for case-insensitive search
	lowerContent := strings.ToLower(htmlContent)
	lowerPayload := strings.ToLower(payload)

	// FIX: Find ALL occurrences of the payload and check each one
	// Return the most dangerous context found
	var mostDangerousContext ContextType = ContextHTML

	offset := 0
	for {
		payloadIdx := strings.Index(lowerContent[offset:], lowerPayload)
		if payloadIdx == -1 {
			break
		}
		
		// Adjust index to global position
		globalIdx := offset + payloadIdx

		// Check context for this occurrence
		ctx := classifyContextAtPosition(lowerContent, globalIdx)

		// Keep the most dangerous context (higher priority)
		if ctx.priority() > mostDangerousContext.priority() {
			mostDangerousContext = ctx
		}

		// Move offset to search for next occurrence
		offset = globalIdx + len(payload)
		
		// Safety: break if we've searched the entire content
		if offset >= len(lowerContent) {
			break
		}
	}

	return mostDangerousContext
}

// classifyContextAtPosition classifies the context at a specific position in the content
func classifyContextAtPosition(lowerContent string, payloadIdx int) ContextType {
	// Check if payload is in a JSON script block first (most specific)
	if isInJSONScriptBlock(lowerContent, payloadIdx) {
		return ContextJSON
	}

	// Check if payload is in a regular script block
	if isInScriptBlock(lowerContent, payloadIdx) {
		return ContextScript
	}

	// Check if payload is in srcdoc attribute (HTML injection context)
	if isInSrcdocAttribute(lowerContent, payloadIdx) {
		return ContextHTMLInjection
	}

	// Check if payload is in a javascript: URI
	if isInJavaScriptURI(lowerContent, payloadIdx) {
		return ContextScript
	}

	// Check if payload is in an attribute
	if isInAttribute(lowerContent, payloadIdx) {
		return ContextAttribute
	}

	return ContextHTML
}

// isInScriptBlock checks if the payload is within a <script> tag
// FIX: Removed fragile -10 offset and improved tag pairing logic
func isInScriptBlock(content string, payloadIdx int) bool {
	// Find all script opening and closing tags
	scriptOpenMatches := scriptOpeningRegex.FindAllStringIndex(content, -1)
	closingMatches := scriptClosingRegex.FindAllStringIndex(content, -1)

	// Find the most recent opening script tag before the payload
	var relevantOpenEnd int = -1
	for _, match := range scriptOpenMatches {
		if match[1] <= payloadIdx {
			relevantOpenEnd = match[1]
		}
	}

	if relevantOpenEnd == -1 {
		return false
	}

	// Check if there's a closing tag between the opening tag and the payload
	// FIX: Removed the -10 offset, use exact position matching
	for _, match := range closingMatches {
		if match[0] >= relevantOpenEnd && match[0] < payloadIdx {
			// Found a closing tag before the payload, so payload is outside this script block
			return false
		}
		if match[0] > payloadIdx {
			// Found a closing tag after the payload, so payload is inside this script block
			return true
		}
	}

	// No closing tag found after the opening tag, so payload is inside unclosed script
	return true
}

// isInJSONScriptBlock checks if the payload is within a <script type="application/json"> tag
// FIX: Improved logic to properly pair JSON script opening and closing tags
func isInJSONScriptBlock(content string, payloadIdx int) bool {
	// Find all JSON script blocks
	jsonMatches := scriptTypeJSONRegex.FindAllStringIndex(content, -1)
	closingMatches := scriptClosingRegex.FindAllStringIndex(content, -1)

	for _, match := range jsonMatches {
		jsonOpenIdx := match[0]
		jsonOpenEnd := match[1]

		// Check if this JSON script block starts before the payload
		if jsonOpenIdx < payloadIdx {
			// Find the FIRST closing tag after this JSON script block opening
			for _, closingMatch := range closingMatches {
				if closingMatch[0] > jsonOpenEnd {
					// Check if payload is between the opening and closing of this JSON script
					if payloadIdx > jsonOpenEnd && payloadIdx < closingMatch[0] {
						return true
					}
					// This closing tag belongs to a different script block
					break
				}
			}
		}
	}

	return false
}

// isInJavaScriptURI checks if the payload is in a javascript: URI
// FIX: Replaced naive 50-character proximity check with proper attribute parsing
func isInJavaScriptURI(content string, payloadIdx int) bool {
	// Walk backward from payload to find the containing attribute
	// Look for the pattern: attr_name="value" or attr_name='value'
	
	// Find the nearest quote before the payload
	quotePos := -1
	quoteChar := byte(0)
	
	for i := payloadIdx - 1; i >= 0 && i >= payloadIdx-2000; i-- {
		if content[i] == '"' || content[i] == '\'' {
			quotePos = i
			quoteChar = content[i]
			break
		}
		// Stop if we hit a tag boundary
		if content[i] == '<' || content[i] == '>' {
			return false
		}
	}
	
	if quotePos == -1 {
		return false
	}
	
	// Find the matching closing quote
	closeQuotePos := -1
	for i := payloadIdx; i < len(content) && i < payloadIdx+2000; i++ {
		if content[i] == quoteChar {
			// Check if it's escaped
			if i > 0 && content[i-1] == '\\' {
				continue
			}
			closeQuotePos = i
			break
		}
	}
	
	if closeQuotePos == -1 {
		return false
	}
	
	// Extract the attribute value
	attrValue := content[quotePos+1:closeQuotePos]
	
	// Check if the attribute value starts with javascript:
	trimmed := strings.TrimSpace(strings.ToLower(attrValue))
	if strings.HasPrefix(trimmed, "javascript:") {
		// Verify this is an executable URL sink (href, src, action, formaction)
		// Walk backward from the opening quote to find the attribute name
		attrNameStart := -1
		for i := quotePos - 1; i >= 0 && i >= quotePos-100; i-- {
			if content[i] == '=' {
				// Found =, now find the attribute name
				for j := i - 1; j >= 0 && j >= i-50; j-- {
					if content[j] == ' ' || content[j] == '\t' || content[j] == '\n' {
						if j+1 < i-1 {
							attrNameStart = j + 1
						}
						break
					}
				}
				break
			}
		}
		
		if attrNameStart != -1 {
			// Find the end of attribute name
			attrNameEnd := quotePos - 1
			for i := quotePos - 1; i >= attrNameStart; i-- {
				if content[i] != ' ' && content[i] != '\t' && content[i] != '\n' && content[i] != '=' {
					attrNameEnd = i
				} else {
					break
				}
			}
			
			if attrNameEnd >= attrNameStart {
				attrName := strings.ToLower(content[attrNameStart:attrNameEnd+1])
				// Check if this is an executable URL sink
				if attrName == "href" || attrName == "src" || attrName == "action" || attrName == "formaction" {
					return true
				}
			}
		}
	}
	
	return false
}

// isInAttribute checks if the payload is within an HTML attribute value
// FIX: Now handles escaped quotes properly
func isInAttribute(content string, payloadIdx int) bool {
	if payloadIdx == 0 {
		return false
	}

	// Look backward from payload position to find if we're in an attribute
	beforePayload := content[:payloadIdx]

	// Find the position of the last < to identify tag boundary
	lastOpenBracket := strings.LastIndex(beforePayload, "<")
	if lastOpenBracket == -1 {
		return false
	}

	// Content between < and payload should contain = and quotes for it to be an attribute
	betweenTagAndPayload := beforePayload[lastOpenBracket:]

	// FIX: Count quotes while ignoring escaped quotes
	doubleQuotes := countUnescapedQuotes(betweenTagAndPayload, '"')
	singleQuotes := countUnescapedQuotes(betweenTagAndPayload, '\'')

	// If we have unmatched quotes, we're likely in an attribute
	isInDoubleQuoted := doubleQuotes%2 == 1
	isInSingleQuoted := singleQuotes%2 == 1

	return (isInDoubleQuoted || isInSingleQuoted) && strings.Contains(betweenTagAndPayload, "=")
}

// countUnescapedQuotes counts quotes that are not escaped with backslash
func countUnescapedQuotes(s string, quote byte) int {
	count := 0
	for i := 0; i < len(s); i++ {
		if s[i] == quote {
			// Check if it's escaped
			if i > 0 && s[i-1] == '\\' {
				continue
			}
			count++
		}
	}
	return count
}

// isInSrcdocAttribute checks if the payload is in a srcdoc attribute
// FIX: Improved boundary detection to avoid matching text content
func isInSrcdocAttribute(content string, payloadIdx int) bool {
	// Find srcdoc attribute positions before the payload
	beforePayload := content[:payloadIdx]
	srcdocIdx := strings.LastIndex(beforePayload, "srcdoc")
	
	if srcdocIdx == -1 {
		return false
	}

	// Verify it's actually an attribute (must be inside a tag)
	// Find the last < before srcdoc
	lastOpenBracket := strings.LastIndex(beforePayload[:srcdocIdx], "<")
	lastCloseBracket := strings.LastIndex(beforePayload[:srcdocIdx], ">")
	
	// srcdoc must be after the last < and there should be no > between < and srcdoc
	if lastOpenBracket == -1 || lastCloseBracket > lastOpenBracket {
		return false
	}

	// Verify srcdoc is preceded by whitespace (it's an attribute name)
	if srcdocIdx > 0 {
		prevChar := content[srcdocIdx-1]
		if prevChar != ' ' && prevChar != '\t' && prevChar != '\n' && prevChar != '\r' {
			return false
		}
	}

	// Find the = after srcdoc
	afterSrcdoc := content[srcdocIdx:]
	equalsIdx := strings.Index(afterSrcdoc, "=")
	if equalsIdx == -1 {
		return false
	}

	// Find the opening quote after =
	afterEquals := afterSrcdoc[equalsIdx+1:]
	quoteIdx := -1
	quoteChar := byte(0)
	for i := 0; i < len(afterEquals) && i < 10; i++ {
		if afterEquals[i] == '"' || afterEquals[i] == '\'' {
			quoteIdx = i
			quoteChar = afterEquals[i]
			break
		}
	}
	
	if quoteIdx == -1 {
		return false
	}

	// Find the closing quote
	attrValueStart := srcdocIdx + equalsIdx + 1 + quoteIdx + 1
	attrValueEnd := -1
	for i := attrValueStart; i < len(content) && i < attrValueStart+10000; i++ {
		if content[i] == quoteChar {
			// Check if it's escaped
			if i > 0 && content[i-1] == '\\' {
				continue
			}
			attrValueEnd = i
			break
		}
	}
	
	if attrValueEnd == -1 {
		return false
	}

	// Check if payload is within the srcdoc attribute value
	return payloadIdx > attrValueStart && payloadIdx < attrValueEnd
}

// priority returns the priority of a context (higher = more dangerous)
func (ct ContextType) priority() int {
	switch ct {
	case ContextScript:
		return 5
	case ContextHTMLInjection:
		return 4
	case ContextAttribute:
		return 3
	case ContextHTML:
		return 2
	case ContextJSON:
		return 1
	default:
		return 0
	}
}

// String returns a string representation of the ContextType
func (ct ContextType) String() string {
	switch ct {
	case ContextHTML:
		return "HTML"
	case ContextAttribute:
		return "Attribute"
	case ContextScript:
		return "Script"
	case ContextJSON:
		return "JSON"
	case ContextHTMLInjection:
		return "HTMLInjection"
	default:
		return "Unknown"
	}
}
