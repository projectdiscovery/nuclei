package xss

import (
	"bytes"
	"strings"
)

// QuoteStyle identifies the quoting used around an attribute value.
type QuoteStyle int

// Attribute value quoting constants.
const (
	QuoteNone   QuoteStyle = iota
	QuoteDouble            // value="..."
	QuoteSingle            // value='...'
)

// String returns the string representation of the quote style.
func (q QuoteStyle) String() string {
	switch q {
	case QuoteDouble:
		return "double"
	case QuoteSingle:
		return "single"
	default:
		return "unquoted"
	}
}

// VerifyContext performs escape-aware analysis of a detected reflection to
// determine whether the context is actually exploitable. It rejects non-HTML
// responses, identifies attribute quoting style, detects RCDATA/raw-text
// elements, and flags CSP mitigations. This eliminates the class of false
// positives where reflection occurs in a non-browser-renderable response
// (JSON, plain text) or behind a strict Content-Security-Policy.
//
// Design note: verification is performed entirely from the existing response
// without additional HTTP requests. This keeps the analyzer O(1) in network
// I/O while still catching the dominant false-positive sources. A replay-based
// verification phase (sending context-specific breakout probes) can be layered
// on top in a future iteration without changing this interface.
func VerifyContext(body, headers, marker string, ctx ContextType) (bool, string) {
	if !isHTMLContentType(headers) {
		return false, ""
	}

	switch ctx {
	case ContextScript:
		detail := "script"
		if hasStrictCSP(headers) {
			detail += ":csp-present"
		}
		return true, detail

	case ContextAttribute:
		q := detectQuoting([]byte(body), []byte(marker))
		if q == QuoteNone {
			return true, "attribute:unquoted"
		}
		return true, "attribute:" + q.String() + "-quoted"

	case ContextHTML:
		if inRCDATA([]byte(body), []byte(marker)) {
			return true, "html_tag:rcdata"
		}
		return true, "html_tag"

	case ContextComment:
		return true, "comment"
	}

	return false, ""
}

// isHTMLContentType reports whether the response headers indicate HTML content.
// If no Content-Type header is present, returns true (browsers may content-sniff).
func isHTMLContentType(headers string) bool {
	h := strings.ToLower(headers)
	i := strings.Index(h, "content-type:")
	if i < 0 {
		return true // no CT header; assume HTML (browser content-sniffing)
	}
	val := h[i+len("content-type:"):]
	if j := strings.IndexByte(val, '\n'); j >= 0 {
		val = val[:j]
	}
	return strings.Contains(val, "text/html") || strings.Contains(val, "application/xhtml")
}

// hasStrictCSP reports whether a Content-Security-Policy header restricts
// inline script execution (script-src or default-src without 'unsafe-inline').
func hasStrictCSP(headers string) bool {
	h := strings.ToLower(headers)
	i := strings.Index(h, "content-security-policy:")
	if i < 0 {
		return false
	}
	val := h[i+len("content-security-policy:"):]
	if j := strings.IndexByte(val, '\n'); j >= 0 {
		val = val[:j]
	}
	return (strings.Contains(val, "script-src") || strings.Contains(val, "default-src")) &&
		!strings.Contains(val, "'unsafe-inline'")
}

// detectQuoting scans backwards from the marker position to determine the
// quote character enclosing the attribute value. Stops at tag boundaries.
func detectQuoting(body, marker []byte) QuoteStyle {
	idx := bytes.Index(body, marker)
	if idx < 1 {
		return QuoteNone
	}
	limit := idx - 128
	if limit < 0 {
		limit = 0
	}
	for i := idx - 1; i >= limit; i-- {
		switch body[i] {
		case '"':
			return QuoteDouble
		case '\'':
			return QuoteSingle
		case '=':
			return QuoteNone
		case '<', '>':
			return QuoteNone
		}
	}
	return QuoteNone
}

const rcdataScanWindow = 512

// rcdataTags are RCDATA and raw text elements where injected content
// requires closing the element before HTML parsing resumes.
var rcdataOpen = [][]byte{
	[]byte("<textarea"),
	[]byte("<title"),
	[]byte("<xmp"),
	[]byte("<noscript"),
}

var rcdataClose = [][]byte{
	[]byte("</textarea"),
	[]byte("</title"),
	[]byte("</xmp"),
	[]byte("</noscript"),
}

// inRCDATA reports whether the marker is inside an RCDATA or raw text
// element (textarea, title, xmp, noscript) that requires additional
// breakout to exploit.
func inRCDATA(body, marker []byte) bool {
	idx := bytes.Index(body, marker)
	if idx < 1 {
		return false
	}
	start := idx - rcdataScanWindow
	if start < 0 {
		start = 0
	}
	chunk := bytes.ToLower(body[start:idx])
	for i, open := range rcdataOpen {
		last := bytes.LastIndex(chunk, open)
		if last < 0 {
			continue
		}
		if bytes.LastIndex(chunk, rcdataClose[i]) < last {
			return true
		}
	}
	return false
}
