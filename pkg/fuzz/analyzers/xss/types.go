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

// javascriptURIAttrs are attributes that can contain javascript: URIs
var javascriptURIAttrs = map[string]struct{}{
	"href":       {},
	"src":        {},
	"action":     {},
	"formaction": {},
	"data":       {},
	"xlink:href": {},
}

// isJavascriptURI returns true if the attribute value starts with "javascript:"
// and the attribute is one that browsers will execute (href, src, action, etc.)
func isJavascriptURI(attrName, attrVal string) bool {
	if _, ok := javascriptURIAttrs[strings.ToLower(attrName)]; !ok {
		return false
	}
	trimmed := strings.TrimSpace(attrVal)
	return strings.HasPrefix(strings.ToLower(trimmed), "javascript:")
}

// nonExecutableScriptTypes are MIME types for <script> blocks that browsers
// do not execute as JavaScript.
var nonExecutableScriptTypes = map[string]struct{}{
	"application/json":    {},
	"application/ld+json": {},
	"importmap":           {},
	"speculationrules":    {},
	"application/xml":     {},
	"text/html":           {},
	"text/plain":          {},
	"text/template":       {},
	"text/x-template":     {},
}

// isNonExecutableScriptType checks the raw token of a <script> tag to determine
// if it has a type attribute that indicates non-executable content.
func isNonExecutableScriptType(rawToken string) bool {
	rawLower := strings.ToLower(rawToken)
	idx := strings.Index(rawLower, "type=")
	if idx < 0 {
		return false // no type attribute means default (text/javascript) — executable
	}
	after := rawLower[idx+5:]
	// Strip quote character if present
	if len(after) > 0 && (after[0] == '"' || after[0] == '\'') {
		quote := after[0]
		after = after[1:]
		end := strings.IndexByte(after, quote)
		if end >= 0 {
			after = after[:end]
		}
	} else {
		// Unquoted — read until space or >
		end := strings.IndexAny(after, " \t\n\r>")
		if end >= 0 {
			after = after[:end]
		}
	}
	scriptType := strings.TrimSpace(after)
	_, nonExec := nonExecutableScriptTypes[scriptType]
	return nonExec
}

// rcdataElements are HTML elements whose content is treated as RCDATA (no tag parsing)
var rcdataElements = map[string]struct{}{
	"textarea": {},
	"title":    {},
	"xmp":      {},
	"noscript": {},
}
