package xss

import "strings"

// ContextType classifies the HTML parsing context where a reflected value
// was found. Each context requires different escape sequences to achieve
// script execution, so knowing the context drives payload selection.
type ContextType int

const (
	// ContextNone means the marker was not found in the response body.
	ContextNone ContextType = iota
	// ContextHTMLComment means the marker appeared inside an HTML comment.
	ContextHTMLComment
	// ContextHTMLText means the marker appeared in normal HTML body text
	// (between tags, outside any special parsing context).
	ContextHTMLText
	// ContextAttribute means the marker appeared inside a quoted or
	// unquoted HTML attribute value.
	ContextAttribute
	// ContextAttributeUnquoted is like ContextAttribute but specifically
	// for unquoted attribute values, which have different breakout rules.
	ContextAttributeUnquoted
	// ContextScript means the marker appeared inside a <script> block
	// or inside a JavaScript event-handler attribute.
	ContextScript
	// ContextScriptString is a sub-context of ContextScript where the
	// marker is inside a quoted JS string literal.
	ContextScriptString
	// ContextStyle means the marker appeared inside a <style> block.
	ContextStyle
)

// String returns a human-readable label for the context type, useful for
// debug logging and result reporting.
func (c ContextType) String() string {
	switch c {
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
		return "none"
	}
}

// CharacterSet tracks which characters survived server-side processing
// (sanitization, encoding, WAF filtering). We send a canary that
// includes special characters and then check which ones appear
// unmodified in the response.
type CharacterSet struct {
	AngleBrackets bool // < and >
	SingleQuote   bool // '
	DoubleQuote   bool // "
	ForwardSlash  bool // /
	Backtick      bool // `
	Parentheses   bool // ( and )
	Equals        bool // =
}

// ReflectionInfo describes a single location where the marker was
// reflected in the response, along with the parsing context and the
// set of characters that survived encoding/filtering at that location.
type ReflectionInfo struct {
	// Context is the HTML parsing context at this reflection point.
	Context ContextType
	// Position is the byte offset within the response body where the
	// marker was found.
	Position int
	// AttributeName is set when the reflection is inside an attribute.
	// It holds the lowercase attribute name for context-specific decisions
	// (e.g. distinguishing href from class).
	AttributeName string
	// Chars records which payload-critical characters survived the
	// server's encoding/filtering pipeline at this reflection point.
	Chars CharacterSet
}

// eventHandlers is the set of JavaScript event-handler attribute names.
// When a reflected value lands inside one of these, the context is
// effectively JavaScript rather than plain attribute.
var eventHandlers = map[string]struct{}{
	"onabort":             {},
	"onafterprint":        {},
	"onanimationend":      {},
	"onanimationiteration": {},
	"onanimationstart":    {},
	"onauxclick":          {},
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
	"onfullscreenerror":   {},
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
	"onlostpointercapture": {},
	"onmessage":           {},
	"onmousedown":         {},
	"onmouseenter":        {},
	"onmouseleave":        {},
	"onmousemove":         {},
	"onmouseout":          {},
	"onmouseover":         {},
	"onmouseup":           {},
	"onoffline":           {},
	"ononline":            {},
	"onopen":              {},
	"onpagehide":          {},
	"onpageshow":          {},
	"onpaste":             {},
	"onpause":             {},
	"onplay":              {},
	"onplaying":           {},
	"onpointercancel":     {},
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

// isEventHandler returns true if the attribute name (given as a byte slice)
// is a known JavaScript event handler. The check is case-insensitive and
// avoids heap allocation on the hot path by using a stack-allocated buffer
// for the lowercase conversion.
func isEventHandler(attr []byte) bool {
	if len(attr) < 4 || len(attr) > 28 {
		return false
	}
	// Fast prefix check without allocation: 'o' and 'n'
	if (attr[0]|0x20) != 'o' || (attr[1]|0x20) != 'n' {
		return false
	}
	// Lowercase into stack buffer to avoid heap escape for the map lookup.
	var buf [28]byte
	n := copy(buf[:], attr)
	for i := 0; i < n; i++ {
		if buf[i] >= 'A' && buf[i] <= 'Z' {
			buf[i] += 0x20
		}
	}
	_, ok := eventHandlers[string(buf[:n])]
	return ok
}

// isEventHandlerString is a convenience wrapper for string attribute names.
func isEventHandlerString(name string) bool {
	lower := strings.ToLower(name)
	_, ok := eventHandlers[lower]
	return ok
}

// DetectAvailableChars sends the canary with test characters embedded
// and determines which of the characters survived encoding/filtering
// by checking whether they appear in the reflected body. If a character
// was not part of the original canary it is conservatively marked as
// available (we cannot tell whether it would be filtered).
func DetectAvailableChars(body, marker string) CharacterSet {
	cs := CharacterSet{}

	// The canary value that was injected. If the marker contains the
	// test characters, we check if those survived in the response. If it
	// does not, we assume they are available (conservative default).
	cs.AngleBrackets = markerCharSurvived(body, marker, "<") && markerCharSurvived(body, marker, ">")
	cs.SingleQuote = markerCharSurvived(body, marker, "'")
	cs.DoubleQuote = markerCharSurvived(body, marker, "\"")
	cs.ForwardSlash = markerCharSurvived(body, marker, "/")
	cs.Backtick = markerCharSurvived(body, marker, "`")
	cs.Parentheses = markerCharSurvived(body, marker, "(") && markerCharSurvived(body, marker, ")")
	cs.Equals = markerCharSurvived(body, marker, "=")

	return cs
}

// markerCharSurvived checks whether a test character that was embedded
// alongside the marker has survived encoding. If the marker itself does
// not contain the character, we return true (conservative: assume
// available since we could not test it).
func markerCharSurvived(body, marker, char string) bool {
	if !strings.Contains(marker, char) {
		return true
	}
	// The character was in the canary; it survived if it still appears
	// near the marker in the response body.
	return strings.Contains(body, marker)
}
