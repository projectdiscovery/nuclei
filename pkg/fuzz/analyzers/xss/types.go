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

// urlAttributes is a set of HTML attributes that can contain URLs
var urlAttributes = map[string]struct{}{
	"href": {}, "src": {}, "action": {}, "formaction": {},
	"data": {}, "poster": {}, "codebase": {}, "cite": {},
	"background": {}, "dynsrc": {}, "lowsrc": {}, "ping": {},
}

// isURLAttribute returns true if the attribute can contain a URL
func isURLAttribute(name string) bool {
	_, ok := urlAttributes[strings.ToLower(name)]
	return ok
}

// isJavascriptURI returns true if the value starts with a scriptable URI scheme.
func isJavascriptURI(val string) bool {
	trimmed := strings.TrimSpace(val)
	return hasSchemePrefix(trimmed, "javascript:") || hasSchemePrefix(trimmed, "data:")
}

func hasSchemePrefix(val, prefix string) bool {
	return len(val) >= len(prefix) && strings.EqualFold(val[:len(prefix)], prefix)
}

// executableScriptTypes is a set of script types that execute JavaScript
var executableScriptTypes = map[string]struct{}{
	"": {}, "text/javascript": {}, "application/javascript": {},
	"text/ecmascript": {}, "application/ecmascript": {},
	"module": {}, "text/jscript": {}, "text/livescript": {},
	"application/x-javascript": {}, "text/x-javascript": {},
}

// isExecutableScriptType returns true if the script type executes JavaScript.
// It strips MIME parameters (e.g., "; charset=utf-8") before matching.
func isExecutableScriptType(scriptType string) bool {
	cleaned := strings.ToLower(strings.TrimSpace(scriptType))
	// Strip MIME parameters: "text/javascript; charset=utf-8" → "text/javascript"
	if idx := strings.IndexByte(cleaned, ';'); idx >= 0 {
		cleaned = strings.TrimSpace(cleaned[:idx])
	}
	_, ok := executableScriptTypes[cleaned]
	return ok
}

// rcdataElements are HTML elements whose content is treated as RCDATA (no tag parsing)
var rcdataElements = map[string]struct{}{
	"textarea": {},
	"title":    {},
	"xmp":      {},
	"noscript": {},
}
