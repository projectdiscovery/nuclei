// Package xss implements a context-aware XSS (Cross-Site Scripting) analyzer
// for detecting reflected XSS vulnerabilities through intelligent payload selection.
//
// The analyzer works in three phases:
//
//  1. Context Detection: A canary probe (containing special characters like <>'"/`)
//     is sent to identify where and how user input is reflected in the response.
//     The analyzer detects various HTML contexts including:
//     - HTML body (<div>CANARY</div>)
//     - Quoted/unquoted attributes (<input value="CANARY">)
//     - JavaScript blocks and strings (<script>var x = "CANARY"</script>)
//     - URL attributes (<a href="CANARY">)
//     - Style blocks and HTML comments
//
//  2. Payload Selection: Based on the detected context and available characters
//     (which special chars survived encoding), appropriate XSS payloads are
//     selected. For example, attribute contexts get breakout payloads like
//     "><script>alert(1)</script>, while script contexts get payloads like
//     ";alert(1);//
//
//  3. Verification: Selected payloads are sent and the response is analyzed to
//     confirm the payload landed in an exploitable position without being
//     encoded or placed in a non-executable context (like HTML comments).
//
// Scope and Limitations:
//   - This analyzer focuses on REFLECTED XSS detection only
//   - DOM-based XSS is out of scope as it requires JavaScript execution analysis
//   - Stored XSS detection depends on the fuzzing workflow, not this analyzer
//
// The context detection approach is inspired by browser-based XSS auditors and
// provides accurate context identification to minimize false positives while
// maximizing detection of real vulnerabilities.
package xss

// ContextType represents where in the HTML the reflection occurred
type ContextType int

const (
	ContextUnknown               ContextType = iota
	ContextHTMLBody                          // <div>CANARY</div>
	ContextHTMLAttributeQuoted               // <input value="CANARY">
	ContextHTMLAttributeUnquoted             // <input value=CANARY>
	ContextScriptBlock                       // <script>var x = "CANARY"</script>
	ContextScriptString                      // Inside JS string
	ContextScriptTemplateLiteral             // Inside JS template literal: `template ${CANARY}`
	ContextHTMLComment                       // <!-- CANARY -->
	ContextStyleBlock                        // <style>...CANARY...</style>
	ContextURLAttribute                      // <a href="CANARY">
)

// String returns the string representation of ContextType
func (c ContextType) String() string {
	switch c {
	case ContextHTMLBody:
		return "HTML_BODY"
	case ContextHTMLAttributeQuoted:
		return "HTML_ATTRIBUTE_QUOTED"
	case ContextHTMLAttributeUnquoted:
		return "HTML_ATTRIBUTE_UNQUOTED"
	case ContextScriptBlock:
		return "SCRIPT_BLOCK"
	case ContextScriptString:
		return "SCRIPT_STRING"
	case ContextScriptTemplateLiteral:
		return "SCRIPT_TEMPLATE_LITERAL"
	case ContextHTMLComment:
		return "HTML_COMMENT"
	case ContextStyleBlock:
		return "STYLE_BLOCK"
	case ContextURLAttribute:
		return "URL_ATTRIBUTE"
	default:
		return "UNKNOWN"
	}
}

// ReflectionInfo contains details about a reflection point
type ReflectionInfo struct {
	Position       int          // Byte offset in response
	Context        ContextType  // Detected context
	AvailableChars CharacterSet // Which special chars survived encoding
	BeforeCanary   string       // 200 chars before canary
	AfterCanary    string       // 200 chars after canary
	AttributeName  string       // For attribute contexts
	QuoteChar      string       // " or ' or empty
}

// CharacterSet tracks which special characters survived encoding
type CharacterSet struct {
	HasLessThan    bool // <
	HasGreaterThan bool // >
	HasSingleQuote bool // '
	HasDoubleQuote bool // "
	HasSlash       bool // /
	HasBacktick    bool // `
}

const (
	// DefaultCanary is the default probe payload with special chars
	DefaultCanary = "xSs9K7j<>'\"/()"
	// AnalyzerName is the identifier for the XSS context analyzer
	AnalyzerName = "xss_context"
	// contextLookbackSize is the number of bytes to look back for context detection
	contextLookbackSize = 500
	// surroundingTextSize is the number of chars to extract before/after canary for analysis
	surroundingTextSize = 200
)

// urlAttributes lists HTML attributes that accept URLs (href, src, etc.) and have
// special XSS considerations (e.g., javascript: protocol).
var urlAttributes = []string{
	"href", "src", "action", "data", "formaction", "poster",
	"codebase", "cite", "background", "dynsrc", "lowsrc", "manifest",
}
