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
	scriptTypeJSONRegex     = regexp.MustCompile(`(?i)<script[^>]*type\s*=\s*["']?application/json["']?[^>]*>`)
	scriptOpeningRegex      = regexp.MustCompile(`(?i)<script[^>]*>`)
	scriptClosingRegex      = regexp.MustCompile(`(?i)</script>`)
	javaScriptURIRegex      = regexp.MustCompile(`(?i)javascript\s*:`)
)

// ClassifyContext determines the context in which a payload appears in the response
func ClassifyContext(htmlContent, payload string) ContextType {
	// Normalize for case-insensitive search
	lowerContent := strings.ToLower(htmlContent)
	lowerPayload := strings.ToLower(payload)

	// Find the position of the payload in the response (case-insensitive)
	payloadIdx := strings.Index(lowerContent, lowerPayload)
	if payloadIdx == -1 {
		return ContextHTML
	}

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
func isInScriptBlock(content string, payloadIdx int) bool {
	// Find all script opening and closing tags
	scriptOpenMatches := scriptOpeningRegex.FindAllStringIndex(content, -1)
	closingMatches := scriptClosingRegex.FindAllStringIndex(content, -1)

	// Find the last opening script tag before the payload
	var lastScriptOpenEnd int
	var foundOpen bool

	for _, match := range scriptOpenMatches {
		if match[0] < payloadIdx {
			lastScriptOpenEnd = match[1]
			foundOpen = true
		}
	}

	if !foundOpen {
		return false
	}

	// Check if there's a closing tag after the last opening tag and before payload
	for _, match := range closingMatches {
		if match[0] > lastScriptOpenEnd-10 && match[0] < payloadIdx {
			return false
		}
		if match[0] > payloadIdx {
			return true
		}
	}

	// No closing tag found after the opening tag
	return true
}

// isInJSONScriptBlock checks if the payload is within a <script type="application/json"> tag
func isInJSONScriptBlock(content string, payloadIdx int) bool {
	// Find if there's a JSON script block that contains the payload
	jsonMatches := scriptTypeJSONRegex.FindAllStringIndex(content, -1)
	closingMatches := scriptClosingRegex.FindAllStringIndex(content, -1)

	for _, match := range jsonMatches {
		jsonOpenIdx := match[0]
		jsonOpenEnd := match[1]

		if jsonOpenIdx < payloadIdx {
			// Find the next closing tag after this JSON script block
			for _, closingMatch := range closingMatches {
				if closingMatch[0] > jsonOpenEnd && closingMatch[0] > payloadIdx {
					return true
				}
			}
		}
	}

	return false
}

// isInJavaScriptURI checks if the payload is in a javascript: URI
func isInJavaScriptURI(content string, payloadIdx int) bool {
	// Look for javascript: pattern nearby the payload
	start := 0
	if payloadIdx > 50 {
		start = payloadIdx - 50
	}

	end := len(content)
	if payloadIdx+50 < len(content) {
		end = payloadIdx + 50
	}

	context := content[start:end]
	return strings.Contains(context, "javascript:")
}

// isInAttribute checks if the payload is within an HTML attribute value
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

	// Check for unmatched quotes
	doubleQuotes := strings.Count(betweenTagAndPayload, "\"")
	singleQuotes := strings.Count(betweenTagAndPayload, "'")

	// If we have unmatched quotes, we're likely in an attribute
	isInDoubleQuoted := doubleQuotes%2 == 1
	isInSingleQuoted := singleQuotes%2 == 1

	return (isInDoubleQuoted || isInSingleQuoted) && strings.Contains(betweenTagAndPayload, "=")
}

// isInSrcdocAttribute checks if the payload is in a srcdoc attribute
func isInSrcdocAttribute(content string, payloadIdx int) bool {
	// Find srcdoc attribute positions
	srcdocIdx := strings.LastIndex(content[:payloadIdx], "srcdoc")
	if srcdocIdx == -1 {
		return false
	}

	// Verify it's actually an attribute (preceded by whitespace and followed by =)
	if srcdocIdx > 0 && !strings.ContainsAny(string(content[srcdocIdx-1]), " \t\n") {
		return false
	}

	// Find the = after srcdoc
	equalsIdx := strings.Index(content[srcdocIdx:payloadIdx], "=")
	if equalsIdx == -1 {
		return false
	}

	// Find the next tag close (>) after the srcdoc
	closeIdx := strings.Index(content[srcdocIdx:], ">")
	if closeIdx == -1 {
		return false
	}

	// Payload must be before the tag close
	return payloadIdx < srcdocIdx+closeIdx
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
