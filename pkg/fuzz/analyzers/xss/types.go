package xss

// ContextType represents the type of context where XSS reflection occurs
type ContextType int

const (
	// ContextHTMLText represents reflection in HTML text nodes (easiest to exploit)
	ContextHTMLText ContextType = iota
	// ContextHTMLAttrUnquoted represents reflection in unquoted HTML attributes
	ContextHTMLAttrUnquoted
	// ContextHTMLAttrSingleQuoted represents reflection in single-quoted HTML attributes
	ContextHTMLAttrSingleQuoted
	// ContextHTMLAttrDoubleQuoted represents reflection in double-quoted HTML attributes
	ContextHTMLAttrDoubleQuoted
	// ContextScriptTemplateString represents reflection in JavaScript template strings
	ContextScriptTemplateString
	// ContextScriptCode represents reflection in JavaScript code
	ContextScriptCode
	// ContextScriptStringSingle represents reflection in single-quoted JavaScript strings
	ContextScriptStringSingle
	// ContextScriptStringDouble represents reflection in double-quoted JavaScript strings
	ContextScriptStringDouble
	// ContextScriptJSON represents reflection in JSON data within script tags (type="application/json")
	ContextScriptJSON
	// ContextHTMLComment represents reflection in HTML comments
	ContextHTMLComment
	// ContextRCDATA represents reflection in RCDATA elements (textarea, title)
	ContextRCDATA
	// ContextStyleProperty represents reflection in CSS style properties
	ContextStyleProperty
	// ContextEventHandler represents reflection in event handler attributes (onclick, etc.)
	ContextEventHandler
	// ContextUnknown represents unknown or unidentified context
	ContextUnknown
)

// String returns the string representation of the context type
func (c ContextType) String() string {
	switch c {
	case ContextHTMLText:
		return "html_text"
	case ContextHTMLAttrUnquoted:
		return "html_attr_unquoted"
	case ContextHTMLAttrSingleQuoted:
		return "html_attr_single_quoted"
	case ContextHTMLAttrDoubleQuoted:
		return "html_attr_double_quoted"
	case ContextScriptTemplateString:
		return "script_template_string"
	case ContextScriptCode:
		return "script_code"
	case ContextScriptStringSingle:
		return "script_string_single"
	case ContextScriptStringDouble:
		return "script_string_double"
	case ContextScriptJSON:
		return "script_json_data"
	case ContextHTMLComment:
		return "html_comment"
	case ContextRCDATA:
		return "rcdata"
	case ContextStyleProperty:
		return "style_property"
	case ContextEventHandler:
		return "event_handler"
	default:
		return "unknown"
	}
}

// ExploitabilityRank returns the difficulty rank of exploiting this context
// Lower rank = easier to exploit
// exploitabilityRanks defines the difficulty rank for each context type
var exploitabilityRanks = map[ContextType]int{
	ContextHTMLText:             1,  // Easiest - direct script injection
	ContextHTMLAttrUnquoted:     2,  // Easy - space breakout
	ContextScriptTemplateString: 3,  // Easy - ${} injection
	ContextHTMLAttrSingleQuoted: 4,  // Medium - quote breakout needed
	ContextHTMLAttrDoubleQuoted: 4,  // Medium - quote breakout needed
	ContextScriptCode:           5,  // Medium - syntax matters
	ContextScriptStringSingle:   6,  // Hard - string escape needed
	ContextScriptStringDouble:   6,  // Hard - string escape needed
	ContextScriptJSON:           10, // Unexploitable - data only, not code
	ContextStyleProperty:        8,  // Very hard - limited vectors
	ContextRCDATA:               7,  // Hard - requires closing tag breakout
	ContextEventHandler:         3,  // Easy - can execute JS directly
	ContextHTMLComment:          9,  // Nearly impossible
	ContextUnknown:              10, // Unknown
}

// ExploitabilityRank returns the difficulty rank of exploiting this context
// Lower rank = easier to exploit
func (c ContextType) ExploitabilityRank() int {
	if rank, ok := exploitabilityRanks[c]; ok {
		return rank
	}
	return 10
}

// ReflectionContext represents a location where the canary was reflected
type ReflectionContext struct {
	// Type is the context type
	Type ContextType
	// Location is the byte offset in the response body
	Location int
	// QuoteChar is the quote character used in attributes (' or " or 0 for unquoted)
	QuoteChar rune
	// TagName is the HTML tag name for attribute contexts
	TagName string
	// FilterBypass contains filter detection results
	FilterBypass FilterBypassInfo
}

// FilterBypassInfo contains information about what filters were detected
type FilterBypassInfo struct {
	// AngleBracketsAllowed indicates if < and > survived without encoding
	AngleBracketsAllowed bool
	// SingleQuoteAllowed indicates if ' survived without encoding
	SingleQuoteAllowed bool
	// DoubleQuoteAllowed indicates if " survived without encoding
	DoubleQuoteAllowed bool
	// IsExploitable indicates if this reflection can be exploited
	IsExploitable bool
	// BlockedChars are the characters that were filtered/encoded
	BlockedChars string
}

// XSSPayload represents a context-specific XSS payload
type XSSPayload struct {
	// Value is the actual payload string (may contain [RAND] placeholder)
	Value string
	// Description explains what the payload does
	Description string
	// VerificationPattern is what to look for in response to confirm XSS
	VerificationPattern string
	// RequiredChars are characters that must be allowed for this payload
	RequiredChars string
}
