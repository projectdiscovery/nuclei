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
	// ContextScriptData means the marker is inside a non-executable script block
	// (e.g. <script type="application/json">). The content is data, not code,
	// but a </script> breakout is still possible.
	ContextScriptData
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
	case ContextScriptData:
		return "script_data"
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
	case ContextScriptData:
		return 1
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
	"onabort":             {},
	"onafterprint":        {},
	"onanimationend":      {},
	"onanimationiteration": {},
	"onanimationstart":    {},
	"onauxclick":          {},
	"onbeforecopy":        {},
	"onbeforecut":         {},
	"onbeforeinput":       {},
	"onbeforepaste":       {},
	"onbeforeprint":       {},
	"onbeforeunload":      {},
	"onblur":              {},
	"oncanplay":           {},
	"oncanplaythrough":    {},
	"onchange":            {},
	"onclick":             {},
	"onclose":             {},
	"oncontextmenu":       {},
	"oncopy":              {},
	"oncuechange":         {},
	"oncut":               {},
	"ondblclick":          {},
	"ondrag":              {},
	"ondragend":           {},
	"ondragenter":         {},
	"ondragleave":         {},
	"ondragover":          {},
	"ondragstart":         {},
	"ondrop":              {},
	"ondurationchange":    {},
	"onemptied":           {},
	"onended":             {},
	"onerror":             {},
	"onfocus":             {},
	"onfocusin":           {},
	"onfocusout":          {},
	"onfullscreenchange":  {},
	"ongotpointercapture": {},
	"onhashchange":        {},
	"oninput":             {},
	"oninvalid":           {},
	"onkeydown":           {},
	"onkeypress":          {},
	"onkeyup":             {},
	"onload":              {},
	"onloadeddata":        {},
	"onloadedmetadata":    {},
	"onloadstart":         {},
	"onmessage":           {},
	"onmousedown":         {},
	"onmouseenter":        {},
	"onmouseleave":        {},
	"onmousemove":         {},
	"onmouseout":          {},
	"onmouseover":         {},
	"onmouseup":           {},
	"onmousewheel":        {},
	"onoffline":           {},
	"ononline":            {},
	"onpagehide":          {},
	"onpageshow":          {},
	"onpaste":             {},
	"onpause":             {},
	"onplay":              {},
	"onplaying":           {},
	"onpointerdown":       {},
	"onpointerenter":      {},
	"onpointerleave":      {},
	"onpointermove":       {},
	"onpointerout":        {},
	"onpointerover":       {},
	"onpointerup":         {},
	"onpopstate":          {},
	"onprogress":          {},
	"onratechange":        {},
	"onreset":             {},
	"onresize":            {},
	"onscroll":            {},
	"onsearch":            {},
	"onseeked":            {},
	"onseeking":           {},
	"onselect":            {},
	"onstalled":           {},
	"onstorage":           {},
	"onsubmit":            {},
	"onsuspend":           {},
	"ontimeupdate":        {},
	"ontoggle":            {},
	"ontouchcancel":       {},
	"ontouchend":          {},
	"ontouchmove":         {},
	"ontouchstart":        {},
	"ontransitionend":     {},
	"onunload":            {},
	"onvolumechange":      {},
	"onwaiting":           {},
	"onwheel":             {},
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

// javascriptURIAttrs are attributes where a javascript: URI is executable
var javascriptURIAttrs = map[string]struct{}{
	"href":       {},
	"src":        {},
	"action":     {},
	"formaction": {},
	"data":       {},
	"poster":     {},
}

// isJavascriptURI checks if the attribute value begins with a javascript: URI scheme.
// Handles mixed case and leading whitespace per the HTML spec.
func isJavascriptURI(attrVal string) bool {
	trimmed := strings.TrimSpace(attrVal)
	return strings.HasPrefix(strings.ToLower(trimmed), "javascript:")
}

// executableScriptTypes are MIME types that browsers treat as executable JavaScript
// inside <script> tags. Any type not in this set (or empty) is non-executable data.
// Reference: https://mimesniff.spec.whatwg.org/#javascript-mime-type
var executableScriptTypes = map[string]struct{}{
	"":                          {}, // no type attribute = executable
	"text/javascript":           {},
	"application/javascript":    {},
	"application/x-javascript":  {},
	"text/ecmascript":           {},
	"application/ecmascript":    {},
	"text/jscript":              {},
	"module":                    {},
}

// isExecutableScriptType returns true if the given script type attribute value
// indicates the script content is executable. Empty string (no type attr) is executable.
func isExecutableScriptType(scriptType string) bool {
	// Strip MIME parameters like ";charset=utf-8"
	mime := strings.TrimSpace(scriptType)
	if idx := strings.IndexByte(mime, ';'); idx >= 0 {
		mime = strings.TrimSpace(mime[:idx])
	}
	_, ok := executableScriptTypes[strings.ToLower(mime)]
	return ok
}

// srcdocAttrs are attributes that allow full HTML injection
var srcdocAttrs = map[string]struct{}{
	"srcdoc": {},
}

// isSrcdocAttr returns true if the attribute is a known HTML injection sink
func isSrcdocAttr(name string) bool {
	_, ok := srcdocAttrs[strings.ToLower(name)]
	return ok
}
