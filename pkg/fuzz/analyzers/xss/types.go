package xss

import "strings"

const (
	// AnalyzerName is the registry name used by fuzz templates.
	AnalyzerName = "xss_context"
	// DefaultCanary is the default marker used for reflection tracking.
	DefaultCanary  = "nuclei9x7q<>\"'`"
	maxReflections = 10
)

// ContextType represents where the marker was reflected in the parsed document.
type ContextType int

const (
	ContextUnknown               ContextType = iota
	ContextHTMLText                          // <div>MARKER</div>
	ContextAttributeDoubleQuoted             // <input value="MARKER">
	ContextAttributeSingleQuoted             // <input value='MARKER'>
	ContextAttributeUnquoted                 // <input value=MARKER>
	ContextEventHandler                      // <div onclick="MARKER">
	ContextScriptBlock                       // <script>MARKER</script>
	ContextScriptStringDouble                // <script>var x="MARKER"</script>
	ContextScriptStringSingle                // <script>var x='MARKER'</script>
	ContextScriptTemplate                    // <script>var x=`MARKER`</script>
	ContextComment                           // <!-- MARKER -->
	ContextRCDATA                            // <textarea>MARKER</textarea>
	ContextStyle                             // <style>MARKER</style>
	ContextURLAttribute                      // <a href="MARKER">
)

// String returns a stable machine-readable context name.
func (c ContextType) String() string {
	switch c {
	case ContextHTMLText:
		return "html_text"
	case ContextAttributeDoubleQuoted:
		return "attr_double_quoted"
	case ContextAttributeSingleQuoted:
		return "attr_single_quoted"
	case ContextAttributeUnquoted:
		return "attr_unquoted"
	case ContextEventHandler:
		return "event_handler"
	case ContextScriptBlock:
		return "script_block"
	case ContextScriptStringDouble:
		return "script_string_double"
	case ContextScriptStringSingle:
		return "script_string_single"
	case ContextScriptTemplate:
		return "script_template"
	case ContextComment:
		return "comment"
	case ContextRCDATA:
		return "rcdata"
	case ContextStyle:
		return "style"
	case ContextURLAttribute:
		return "url_attribute"
	default:
		return "unknown"
	}
}

// CharacterSet tracks special characters that survive reflection unchanged.
type CharacterSet struct {
	LessThan    bool // <
	GreaterThan bool // >
	SingleQuote bool // '
	DoubleQuote bool // "
	Slash       bool // /
	Backtick    bool // `
	Parenthesis bool // (
	Equals      bool // =
}

// ReflectionInfo captures one reflection location and its exploitability hints.
type ReflectionInfo struct {
	Context        ContextType
	AvailableChars CharacterSet
	AttributeName  string
	PriorityWeight int // lower = higher priority (tried first)
	StartIndex     int
	EndIndex       int
}

// isURLAttribute returns true for attributes that accept URL-like values.
func isURLAttribute(name string) bool {
	switch strings.ToLower(name) {
	case "href", "src", "action", "formaction", "poster", "data",
		"codebase", "cite", "background", "dynsrc", "lowsrc", "ping",
		"manifest", "icon", "srcset":
		return true
	default:
		return false
	}
}

// isEventHandler returns true for HTML event handler attributes (onclick, onerror, etc.)
// Uses case-insensitive matching without heap allocation on the hot path.
func isEventHandler(name string) bool {
	if len(name) < 3 {
		return false
	}
	// Stack-allocated lowercase buffer for short attribute names (covers all event handlers)
	var buf [32]byte
	n := len(name)
	if n > 32 {
		return false
	}
	for i := 0; i < n; i++ {
		c := name[i]
		if c >= 'A' && c <= 'Z' {
			buf[i] = c + 32
		} else {
			buf[i] = c
		}
	}
	// Check prefix "on" directly on bytes to avoid string allocation for non-handlers
	if buf[0] != 'o' || buf[1] != 'n' {
		return false
	}
	_, ok := eventHandlers[string(buf[:n])]
	return ok
}

// eventHandlers is the comprehensive set of HTML event handler attribute names.
var eventHandlers = map[string]struct{}{
	// Mouse events
	"onclick": {}, "ondblclick": {}, "onmousedown": {}, "onmouseup": {},
	"onmousemove": {}, "onmouseover": {}, "onmouseout": {},
	"onmouseenter": {}, "onmouseleave": {}, "oncontextmenu": {},
	// Keyboard events
	"onkeydown": {}, "onkeyup": {}, "onkeypress": {},
	// Form events
	"onfocus": {}, "onblur": {}, "onchange": {}, "oninput": {},
	"onsubmit": {}, "onreset": {}, "onselect": {}, "oninvalid": {},
	// Window events
	"onload": {}, "onunload": {}, "onbeforeunload": {},
	"onresize": {}, "onscroll": {}, "onerror": {},
	"onhashchange": {}, "onpopstate": {}, "onstorage": {},
	"onpagehide": {}, "onpageshow": {},
	// Clipboard events
	"oncopy": {}, "oncut": {}, "onpaste": {},
	// Drag events
	"ondrag": {}, "ondragstart": {}, "ondragend": {},
	"ondragover": {}, "ondragenter": {}, "ondragleave": {}, "ondrop": {},
	// Media events
	"onplay": {}, "onpause": {}, "onended": {}, "onvolumechange": {},
	"onseeking": {}, "onseeked": {}, "oncanplay": {}, "ontimeupdate": {},
	// Touch events
	"ontouchstart": {}, "ontouchend": {}, "ontouchmove": {}, "ontouchcancel": {},
	// Pointer events
	"onpointerdown": {}, "onpointerup": {}, "onpointermove": {},
	"onpointerover": {}, "onpointerout": {},
	"onpointerenter": {}, "onpointerleave": {}, "ongotpointercapture": {},
	// Animation / Transition events
	"onanimationstart": {}, "onanimationend": {}, "onanimationiteration": {},
	"ontransitionend": {}, "ontransitionstart": {}, "ontransitionrun": {},
	// Other common events
	"onfocusin": {}, "onfocusout": {}, "ontoggle": {},
	"onwheel": {}, "onafterprint": {}, "onbeforeprint": {},
	"onabort": {}, "oncanplaythrough": {}, "onwaiting": {},
}

// DetectAvailableChars compares the reflected output against the original canary
// to determine which special characters survived server-side encoding.
func DetectAvailableChars(reflected, original string) CharacterSet {
	return CharacterSet{
		LessThan:    !strings.Contains(original, "<") || strings.Contains(reflected, "<"),
		GreaterThan: !strings.Contains(original, ">") || strings.Contains(reflected, ">"),
		SingleQuote: !strings.Contains(original, "'") || strings.Contains(reflected, "'"),
		DoubleQuote: !strings.Contains(original, "\"") || strings.Contains(reflected, "\""),
		Slash:       !strings.Contains(original, "/") || strings.Contains(reflected, "/"),
		Backtick:    !strings.Contains(original, "`") || strings.Contains(reflected, "`"),
		Parenthesis: !strings.Contains(original, "(") || strings.Contains(reflected, "("),
		Equals:      !strings.Contains(original, "=") || strings.Contains(reflected, "="),
	}
}

// DetectDoubleEncoding checks if the server double-encoded special characters.
// e.g. < -> &amp;lt; instead of &lt;
func DetectDoubleEncoding(reflected string) bool {
	return strings.Contains(reflected, "&amp;lt;") ||
		strings.Contains(reflected, "&amp;gt;") ||
		strings.Contains(reflected, "&amp;quot;") ||
		strings.Contains(reflected, "&amp;#") ||
		strings.Contains(reflected, "&amp;apos;")
}

// DetectUnicodeEscape checks if the server used unicode escapes on special chars.
func DetectUnicodeEscape(reflected string) bool {
	return strings.Contains(reflected, "\\u003c") || // <
		strings.Contains(reflected, "\\u003e") || // >
		strings.Contains(reflected, "\\u0022") || // "
		strings.Contains(reflected, "\\u0027") // '
}
