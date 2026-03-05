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
	LessThan    bool // <
	GreaterThan bool // >
	DoubleQuote bool // "
	SingleQuote bool // '
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

// hasJavascriptURI returns true if the attribute value starts with a javascript: or
// data: URI. Both are executable contexts even though they appear in attribute values.
// data: URIs can embed HTML/JS (e.g. data:text/html,<script>alert(1)</script>).
func hasJavascriptURI(attrVal string) bool {
	trimmed := strings.ToLower(strings.TrimSpace(attrVal))
	return strings.HasPrefix(trimmed, "javascript:") || strings.HasPrefix(trimmed, "data:")
}

// isSrcdocAttr returns true if the attribute name is "srcdoc".
// The srcdoc attribute on iframe elements accepts full HTML content,
// making it an HTML injection context rather than a simple attribute.
func isSrcdocAttr(name string) bool {
	return strings.ToLower(name) == "srcdoc"
}

// isExecutableScriptType returns true if the given script type attribute value
// indicates executable JavaScript. Empty type or standard JS types are executable.
// Data types like application/json, application/ld+json, importmap, etc. are NOT.
// MIME type parameters (e.g. "text/javascript; charset=utf-8") are stripped before matching.
func isExecutableScriptType(scriptType string) bool {
	t := strings.TrimSpace(strings.ToLower(scriptType))
	if t == "" {
		return true // no type means JavaScript
	}
	// Strip MIME parameters (e.g. "text/javascript; charset=utf-8" -> "text/javascript")
	if semi := strings.IndexByte(t, ';'); semi != -1 {
		t = strings.TrimSpace(t[:semi])
	}
	// Standard executable JavaScript MIME types
	switch t {
	case "text/javascript",
		"application/javascript",
		"text/ecmascript",
		"application/ecmascript",
		"module":
		return true
	}
	return false
}
