package xss

import "strings"

// Context represents the HTML context where a reflection occurs
type Context int

const (
	// ContextNone means the marker was not found in the response
	ContextNone Context = iota
	// ContextHTMLComment means the marker is inside an HTML comment
	ContextHTMLComment
	// ContextHTMLText means the marker is inside HTML text content
	ContextHTMLText
	// ContextAttribute means the marker is inside a quoted HTML attribute
	ContextAttribute
	// ContextAttributeUnquoted means the marker is inside an unquoted HTML attribute
	ContextAttributeUnquoted
	// ContextScript means the marker is inside a script block
	ContextScript
	// ContextScriptString means the marker is inside a string literal within a script block
	ContextScriptString
	// ContextStyle means the marker is inside a style block
	ContextStyle
)

// String returns the string representation of the context
func (c Context) String() string {
	switch c {
	case ContextNone:
		return "none"
	case ContextHTMLComment:
		return "html_comment"
	case ContextHTMLText:
		return "html_text"
	case ContextAttribute:
		return "attribute"
	case ContextAttributeUnquoted:
		return "attribute_unquoted"
	case ContextScript:
		return "script"
	case ContextScriptString:
		return "script_string"
	case ContextStyle:
		return "style"
	default:
		return "unknown"
	}
}

// priority returns the priority of the context for choosing the best one.
// Higher value = more interesting for exploitation.
func (c Context) priority() int {
	switch c {
	case ContextScript, ContextScriptString:
		return 5
	case ContextAttributeUnquoted:
		return 4
	case ContextAttribute:
		return 3
	case ContextHTMLText:
		return 2
	case ContextStyle:
		return 1
	case ContextHTMLComment:
		return 0
	default:
		return -1
	}
}

// ReflectionInfo holds information about a detected reflection
type ReflectionInfo struct {
	Context   Context
	AttrName  string // attribute name if in attribute context
	QuoteChar byte   // quote character if in attribute context (' or ")
	TagName   string // parent tag name
}

// CharacterSet tracks which XSS-critical characters survived encoding
type CharacterSet struct {
	LessThan     bool // <
	GreaterThan  bool // >
	DoubleQuote  bool // "
	SingleQuote  bool // '
	ForwardSlash bool // /
}

// canaryChars are the characters appended to the canary to check survival
const canaryChars = `<>"'/`

// eventHandlers is a set of known HTML event handler attribute names
var eventHandlers = map[string]struct{}{
	"onabort":              {},
	"onafterprint":         {},
	"onanimationend":       {},
	"onanimationiteration": {},
	"onanimationstart":     {},
	"onauxclick":           {},
	"onbeforecopy":         {},
	"onbeforecut":          {},
	"onbeforeinput":        {},
	"onbeforepaste":        {},
	"onbeforeprint":        {},
	"onbeforeunload":       {},
	"onblur":               {},
	"oncanplay":            {},
	"oncanplaythrough":     {},
	"onchange":             {},
	"onclick":              {},
	"onclose":              {},
	"oncontextmenu":        {},
	"oncopy":               {},
	"oncuechange":          {},
	"oncut":                {},
	"ondblclick":           {},
	"ondrag":               {},
	"ondragend":            {},
	"ondragenter":          {},
	"ondragleave":          {},
	"ondragover":           {},
	"ondragstart":          {},
	"ondrop":               {},
	"ondurationchange":     {},
	"onemptied":            {},
	"onended":              {},
	"onerror":              {},
	"onfocus":              {},
	"onfocusin":            {},
	"onfocusout":           {},
	"onfullscreenchange":   {},
	"ongotpointercapture":  {},
	"onhashchange":         {},
	"oninput":              {},
	"oninvalid":            {},
	"onkeydown":            {},
	"onkeypress":           {},
	"onkeyup":              {},
	"onload":               {},
	"onloadeddata":         {},
	"onloadedmetadata":     {},
	"onloadstart":          {},
	"onmessage":            {},
	"onmousedown":          {},
	"onmouseenter":         {},
	"onmouseleave":         {},
	"onmousemove":          {},
	"onmouseout":           {},
	"onmouseover":          {},
	"onmouseup":            {},
	"onmousewheel":         {},
	"onoffline":            {},
	"ononline":             {},
	"onpagehide":           {},
	"onpageshow":           {},
	"onpaste":              {},
	"onpause":              {},
	"onplay":               {},
	"onplaying":            {},
	"onpointerdown":        {},
	"onpointerenter":       {},
	"onpointerleave":       {},
	"onpointermove":        {},
	"onpointerout":         {},
	"onpointerover":        {},
	"onpointerup":          {},
	"onpopstate":           {},
	"onprogress":           {},
	"onratechange":         {},
	"onreset":              {},
	"onresize":             {},
	"onscroll":             {},
	"onsearch":             {},
	"onseeked":             {},
	"onseeking":            {},
	"onselect":             {},
	"onstalled":            {},
	"onstorage":            {},
	"onsubmit":             {},
	"onsuspend":            {},
	"ontimeupdate":         {},
	"ontoggle":             {},
	"ontouchcancel":        {},
	"ontouchend":           {},
	"ontouchmove":          {},
	"ontouchstart":         {},
	"ontransitionend":      {},
	"onunload":             {},
	"onvolumechange":       {},
	"onwaiting":            {},
	"onwheel":              {},
}

// isEventHandler returns true if the attribute name is a known event handler
func isEventHandler(name string) bool {
	_, ok := eventHandlers[strings.ToLower(name)]
	return ok
}

// rcdataElements are HTML elements whose content is treated as RCDATA (no tag parsing)
var rcdataElements = map[string]struct{}{
	"textarea": {},
	"title":    {},
	"xmp":      {},
	"noscript": {},
}

// nonExecutableScriptTypes contains MIME types that make <script> blocks non-executable.
// Content inside these script blocks is treated as data, not code.
var nonExecutableScriptTypes = map[string]struct{}{
	"application/json":       {},
	"application/ld+json":    {},
	"application/xml":        {},
	"text/template":          {},
	"text/html":              {},
	"text/x-template":        {},
	"text/x-handlebars-template": {},
}

// isExecutableScriptType checks whether a <script> tag's type attribute
// indicates executable JavaScript. If the type is empty, it defaults to
// JavaScript (executable). Known non-executable types return false.
func isExecutableScriptType(scriptType string) bool {
	if scriptType == "" {
		return true // no type attribute defaults to JavaScript
	}
	// Extract MIME type (strip parameters like charset)
	cleaned := strings.TrimSpace(strings.ToLower(scriptType))
	if idx := strings.IndexByte(cleaned, ';'); idx >= 0 {
		cleaned = strings.TrimSpace(cleaned[:idx])
	}
	_, nonExec := nonExecutableScriptTypes[cleaned]
	return !nonExec
}

// htmlInjectionAttrs are attribute names whose values contain HTML that
// should be treated as a full HTML injection context (ContextHTMLText)
// rather than a simple attribute context.
var htmlInjectionAttrs = map[string]struct{}{
	"srcdoc": {},
}

// isHTMLInjectionAttr returns true if the attribute value is parsed as HTML
// by the browser, making it an HTML injection context.
func isHTMLInjectionAttr(name string) bool {
	_, ok := htmlInjectionAttrs[strings.ToLower(name)]
	return ok
}

// isJavascriptURI returns true if the value starts with "javascript:" scheme,
// indicating the attribute value contains executable JavaScript.
func isJavascriptURI(val string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(val))
	return strings.HasPrefix(trimmed, "javascript:")
}
