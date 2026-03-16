package xss

// ContextType represents the type of XSS context
type ContextType int

const (
	// ContextNone - No reflection or non-executable context
	ContextNone ContextType = iota
	
	// ContextHTMLText - HTML text content (between tags)
	// Example: <div>REFLECTION</div>
	ContextHTMLText
	
	// ContextAttribute - HTML attribute value (quoted)
	// Example: <div class="REFLECTION">
	ContextAttribute
	
	// ContextAttributeUnquoted - HTML attribute value (unquoted)
	// Example: <div class=REFLECTION>
	ContextAttributeUnquoted
	
	// ContextScript - JavaScript code context
	// Example: <script>REFLECTION</script>
	ContextScript
	
	// ContextScriptString - JavaScript string context
	// Example: <script>var x = "REFLECTION";</script>
	ContextScriptString
	
	// ContextStyle - CSS style context
	// Example: <style>body { background: REFLECTION; }</style>
	ContextStyle
	
	// ContextHTMLComment - HTML comment context
	// Example: <!-- REFLECTION -->
	ContextHTMLComment
	
	// ContextURL - URL context (href, src attributes)
	// Example: <a href="REFLECTION">
	ContextURL
	
	// ContextSrcDoc - iframe srcdoc attribute (full HTML injection)
	// Example: <iframe srcdoc="REFLECTION">
	ContextSrcDoc
)

// String returns the string representation of ContextType
func (c ContextType) String() string {
	switch c {
	case ContextNone:
		return "ContextNone"
	case ContextHTMLText:
		return "ContextHTMLText"
	case ContextAttribute:
		return "ContextAttribute"
	case ContextAttributeUnquoted:
		return "ContextAttributeUnquoted"
	case ContextScript:
		return "ContextScript"
	case ContextScriptString:
		return "ContextScriptString"
	case ContextStyle:
		return "ContextStyle"
	case ContextHTMLComment:
		return "ContextHTMLComment"
	case ContextURL:
		return "ContextURL"
	case ContextSrcDoc:
		return "ContextSrcDoc"
	default:
		return "ContextUnknown"
	}
}

// IsExecutable returns true if the context allows code execution
func (c ContextType) IsExecutable() bool {
	executableContexts := []ContextType{
		ContextScript,
		ContextScriptString,
		ContextHTMLText,
		ContextAttribute,
		ContextAttributeUnquoted,
		ContextSrcDoc,
		ContextURL,
	}
	
	for _, ctx := range executableContexts {
		if c == ctx {
			return true
		}
	}
	return false
}

// XSSPayload represents an XSS test payload
type XSSPayload struct {
	// Value is the payload string
	Value string
	
	// Name is a descriptive name for the payload
	Name string
	
	// Tags are context tags for the payload
	Tags []ContextType
	
	// Risk is the risk level (1-5)
	Risk int
	
	// Description is a description of what the payload does
	Description string
}

// XSSResult represents the result of XSS analysis
type XSSResult struct {
	// Found indicates if XSS was detected
	Found bool
	
	// Context is the detected context type
	Context ContextType
	
	// Payload is the payload that triggered detection
	Payload string
	
	// Proof is evidence of the vulnerability
	Proof string
	
	// CSP indicates if CSP headers are present
	CSP bool
	
	// CSPValue contains the CSP header value if present
	CSPValue string
}

// CharacterSet represents a set of characters for survival detection
type CharacterSet struct {
	// AngleBrackets < >
	AngleBrackets bool
	
	// Quotes " '
	Quotes bool
	
	// Slash /
	Slash bool
	
	// Equals =
	Equals bool
	
	// Backslash \
	Backslash bool
	
	// Parentheses ( )
	Parentheses bool
	
	// Semicolon ;
	Semicolon bool
}

// CanaryConfig holds the canary configuration
type CanaryConfig struct {
	// Value is the canary string
	Value string
	
	// Markers are special characters to include
	Markers []string
	
	// Encoding is the encoding to use
	Encoding string
}

// DefaultCanary returns the default canary configuration
func DefaultCanary() *CanaryConfig {
	return &CanaryConfig{
		Value:   "NucleiXSSCanary",
		Markers: []string{"<", ">", "'", "\"", "/", "=", "\\"},
	}
}

// DefaultPayloads returns a list of default XSS payloads
func DefaultPayloads() []XSSPayload {
	return []XSSPayload{
		{
			Value:       "<script>alert(1)</script>",
			Name:        "Basic Script Tag",
			Tags:        []ContextType{ContextScript, ContextHTMLText},
			Risk:        5,
			Description: "Basic script tag injection",
		},
		{
			Value:       "<img src=x onerror=alert(1)>",
			Name:        "Image OnError",
			Tags:        []ContextType{ContextHTMLText, ContextAttribute},
			Risk:        5,
			Description: "Image tag with onerror handler",
		},
		{
			Value:       "javascript:alert(1)",
			Name:        "JavaScript URI",
			Tags:        []ContextType{ContextURL, ContextAttribute},
			Risk:        4,
			Description: "JavaScript URI scheme",
		},
		{
			Value:       "\"><script>alert(1)</script>",
			Name:        "Attribute Escape",
			Tags:        []ContextType{ContextAttribute},
			Risk:        5,
			Description: "Break out of attribute context",
		},
		{
			Value:       "</script><script>alert(1)</script>",
			Name:        "Script Close/Open",
			Tags:        []ContextType{ContextScript},
			Risk:        5,
			Description: "Close existing script and inject new one",
		},
		{
			Value:       "<svg onload=alert(1)>",
			Name:        "SVG OnLoad",
			Tags:        []ContextType{ContextHTMLText},
			Risk:        4,
			Description: "SVG element with onload handler",
		},
		{
			Value:       "<body onload=alert(1)>",
			Name:        "Body OnLoad",
			Tags:        []ContextType{ContextHTMLText},
			Risk:        4,
			Description: "Body tag with onload handler",
		},
		{
			Value:       "<iframe srcdoc=\"<script>alert(1)</script>\">",
			Name:        "Iframe SrcDoc",
			Tags:        []ContextType{ContextSrcDoc},
			Risk:        5,
			Description: "Iframe srcdoc injection",
		},
	}
}

// ContextPatterns holds regex patterns for context detection
type ContextPatterns struct {
	Script      string
	Style       string
	Comment     string
	Attribute   string
	URL         string
	SrcDoc      string
	JavaScript  string
	DataType    string
}

// DefaultContextPatterns returns default patterns for context detection
func DefaultContextPatterns() *ContextPatterns {
	return &ContextPatterns{
		Script:      `(?i)<\s*script[^>]*>`,
		Style:       `(?i)<\s*style[^>]*>`,
		Comment:     `<!--[\s\S]*?-->`,
		Attribute:   `\w+\s*=\s*["'][^"']*["']`,
		URL:         `(?i)(href|src|action|data)\s*=\s*["'][^"']*["']`,
		SrcDoc:      `(?i)\bsrcdoc\s*=\s*["']`,
		JavaScript:  `(?i)javascript\s*:`,
		DataType:    `(?i)type\s*=\s*["'](application/(json|ld\+json|importmap)|text/(json|template))["']`,
	}
}

// MIME types that are NOT executable as JavaScript
var NonExecutableMIMETypes = []string{
	"application/json",
	"application/ld+json",
	"application/importmap+json",
	"text/json",
	"text/template",
	"text/html",
	"text/plain",
	"text/css",
	"image/svg+xml",
}

// MIME types that ARE executable as JavaScript
var ExecutableMIMETypes = []string{
	"text/javascript",
	"application/javascript",
	"application/x-javascript",
	"text/ecmascript",
	"application/ecmascript",
	"module",
}

// IsExecutableMIMEType checks if a MIME type is executable as JavaScript
func IsExecutableMIMEType(mimeType string) bool {
	mimeType = strings.ToLower(strings.TrimSpace(mimeType))
	
	// Check against executable whitelist
	for _, execType := range ExecutableMIMETypes {
		if mimeType == execType || strings.HasPrefix(mimeType, execType) {
			return true
		}
	}
	
	// Check against non-executable blacklist
	for _, nonExecType := range NonExecutableMIMETypes {
		if mimeType == nonExecType || strings.HasPrefix(mimeType, nonExecType) {
			return false
		}
	}
	
	// Default: unknown types are treated as potentially executable
	return true
}
