package xss

import (
	"bytes"
	"strings"

	"golang.org/x/net/html"
)

// ContextType represents the HTML reflection context of a marker.
type ContextType int

const (
	ContextNone ContextType = iota
	ContextComment
	ContextHTML
	ContextAttribute
	ContextScript
)

func (c ContextType) String() string {
	switch c {
	case ContextComment:
		return "comment"
	case ContextHTML:
		return "html_tag"
	case ContextAttribute:
		return "attribute"
	case ContextScript:
		return "script"
	default:
		return "none"
	}
}

var (
	onPrefix  = []byte("on")
	scriptTag = []byte("script")
)

// DetectContext returns the highest-priority HTML context where marker appears.
func DetectContext(body string, marker string) ContextType {
	if !strings.Contains(body, marker) {
		return ContextNone
	}

	m := []byte(marker)
	z := html.NewTokenizer(strings.NewReader(body))

	var (
		inScript bool
		best     = ContextNone
	)

	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return best

		case html.CommentToken:
			if bytes.Contains(z.Text(), m) {
				if best < ContextComment {
					best = ContextComment
				}
			}

		case html.StartTagToken, html.SelfClosingTagToken:
			tn, hasAttr := z.TagName()
			if tt == html.StartTagToken && len(tn) == 6 && bytes.EqualFold(tn, scriptTag) {
				inScript = true
			}
			if hasAttr {
				for {
					k, v, more := z.TagAttr()
					if bytes.Contains(v, m) {
						if len(k) >= 2 && bytes.EqualFold(k[:2], onPrefix) && isEventHandler(k) {
							return ContextScript
						}
						if best < ContextAttribute {
							best = ContextAttribute
						}
					}
					if bytes.Contains(k, m) {
						if best < ContextAttribute {
							best = ContextAttribute
						}
					}
					if !more {
						break
					}
				}
			}

		case html.EndTagToken:
			tn, _ := z.TagName()
			if len(tn) == 6 && bytes.EqualFold(tn, scriptTag) {
				inScript = false
			}

		case html.TextToken:
			if bytes.Contains(z.Text(), m) {
				if inScript {
					return ContextScript
				}
				if best < ContextHTML {
					best = ContextHTML
				}
			}
		}
	}
}

func isEventHandler(key []byte) bool {
	const maxLen = 32
	if len(key) > maxLen {
		return false
	}
	var buf [maxLen]byte
	n := len(key)
	for i := 0; i < n; i++ {
		c := key[i]
		if c >= 'A' && c <= 'Z' {
			buf[i] = c + 0x20
		} else {
			buf[i] = c
		}
	}
	_, ok := eventHandlers[string(buf[:n])]
	return ok
}

var eventHandlers = map[string]struct{}{
	// Window events
	"onafterprint":  {},
	"onbeforeprint": {},
	"onbeforeunload": {},
	"onerror":       {},
	"onhashchange":  {},
	"onload":        {},
	"onmessage":     {},
	"onoffline":     {},
	"ononline":      {},
	"onpagehide":    {},
	"onpageshow":    {},
	"onpopstate":    {},
	"onresize":      {},
	"onstorage":     {},
	"onunload":      {},
	// Form events
	"onblur":        {},
	"onchange":      {},
	"oncontextmenu": {},
	"onfocus":       {},
	"oninput":       {},
	"oninvalid":     {},
	"onreset":       {},
	"onsearch":      {},
	"onselect":      {},
	"onsubmit":      {},
	// Keyboard events
	"onkeydown":  {},
	"onkeypress": {},
	"onkeyup":    {},
	// Mouse events
	"onclick":      {},
	"ondblclick":   {},
	"onmousedown":  {},
	"onmousemove":  {},
	"onmouseout":   {},
	"onmouseover":  {},
	"onmouseup":    {},
	"onwheel":      {},
	// Drag events
	"ondrag":      {},
	"ondragend":   {},
	"ondragenter": {},
	"ondragleave": {},
	"ondragover":  {},
	"ondragstart": {},
	"ondrop":      {},
	// Scroll
	"onscroll": {},
	// Clipboard
	"oncopy":  {},
	"oncut":   {},
	"onpaste": {},
	// Media events
	"onabort":          {},
	"oncanplay":        {},
	"oncanplaythrough": {},
	"ondurationchange": {},
	"onemptied":        {},
	"onended":          {},
	"onloadeddata":     {},
	"onloadedmetadata": {},
	"onloadstart":      {},
	"onpause":          {},
	"onplay":           {},
	"onplaying":        {},
	"onprogress":       {},
	"onratechange":     {},
	"onseeked":         {},
	"onseeking":        {},
	"onstalled":        {},
	"onsuspend":        {},
	"ontimeupdate":     {},
	"onvolumechange":   {},
	"onwaiting":        {},
	// Misc
	"ontoggle":             {},
	"onanimationstart":     {},
	"onanimationend":       {},
	"onanimationiteration": {},
	"ontransitionend":      {},
	"onfocusin":            {},
	"onfocusout":           {},
	"onpointerdown":        {},
	"onpointerup":          {},
	"onpointermove":        {},
	"onpointerover":        {},
	"onpointerout":         {},
	"onpointerenter":       {},
	"onpointerleave":       {},
}
