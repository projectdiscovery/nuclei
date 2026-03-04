package xss

import (
	"io"
	"regexp"
	"strings"

	"github.com/antchfx/htmlquery"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"github.com/projectdiscovery/retryablehttp-go"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// Analyzer is an XSS context analyzer for the fuzzer
type Analyzer struct {
}

// ContextType represents the type of XSS context
type ContextType string

const (
	// ContextTypeNone means no XSS context detected
	ContextTypeNone ContextType = "none"
	// ContextTypeHTMLContent means the payload is in HTML content
	ContextTypeHTMLContent ContextType = "html-content"
	// ContextTypeHTMLAttribute means the payload is in an HTML attribute
	ContextTypeHTMLAttribute ContextType = "html-attribute"
	// ContextTypeJavaScript means the payload is in a JavaScript context
	ContextTypeJavaScript ContextType = "javascript"
	// ContextTypeJavaScriptURI means the payload is in a javascript: URI
	ContextTypeJavaScriptURI ContextType = "javascript-uri"
	// ContextTypeSrcDoc means the payload is in a srcdoc attribute
	ContextTypeSrcDoc ContextType = "srcdoc"
	// ContextTypeStyle means the payload is in a style attribute or context
	ContextTypeStyle ContextType = "style"
	// ContextTypeURL means the payload is in a URL context
	ContextTypeURL ContextType = "url"
	// ContextTypeEventHandler means the payload is in an event handler
	ContextTypeEventHandler ContextType = "event-handler"
)

var _ analyzers.Analyzer = &Analyzer{}

func init() {
	analyzers.RegisterAnalyzer("xss", &Analyzer{})
}

// Name returns the name of the analyzer
func (a *Analyzer) Name() string {
	return "xss"
}

// ApplyInitialTransformation applies the transformation to the initial payload.
// Currently returns the data as-is since XSS analysis doesn't need payload transformation.
func (a *Analyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	return data
}

// javascriptURIRegex matches javascript: and vbscript: URIs
var javascriptURIRegex = regexp.MustCompile(`(?i)^(javascript|vbscript):`)

// srcdocAttrRegex matches srcdoc attributes
var srcdocAttrRegex = regexp.MustCompile(`(?i)\bsrcdoc\s*=`)

// eventHandlerAttrs is a list of event handler attributes that execute JavaScript
var eventHandlerAttrs = map[string]bool{
	"onclick":      true,
	"onload":       true,
	"onerror":      true,
	"onmouseover":  true,
	"onfocus":      true,
	"onblur":       true,
	"onchange":     true,
	"onsubmit":     true,
	"onreset":      true,
	"onselect":     true,
	"onkeydown":    true,
	"onkeyup":      true,
	"onkeypress":   true,
	"onmousedown":  true,
	"onmouseup":    true,
	"onmouseout":   true,
	"onmousemove":  true,
	"onhover":      true,
	"onabort":      true,
	"oncanplay":    true,
	"oncanplaythrough": true,
	"ondurationchange":  true,
	"onemptied":    true,
	"onended":      true,
	"onloadeddata": true,
	"onloadedmetadata": true,
	"onloadstart": true,
	"onpause":     true,
	"onplay":       true,
	"onplaying":    true,
	"onprogress":   true,
	"onratechange": true,
	"onseeked":     true,
	"onseeking":    true,
	"onstalled":    true,
	"onsuspend":    true,
	"ontimeupdate": true,
	"onvolumechange": true,
	"onwaiting":    true,
	"ondrag":       true,
	"ondragend":    true,
	"ondragenter":  true,
	"ondragleave":  true,
	"ondragover":   true,
	"ondragstart":  true,
	"ondrop":       true,
	"oncontextmenu": true,
	"onhashchange": true,
	"onpageshow":   true,
	"onpagehide":  true,
	"onpopstate":  true,
	"onstorage":   true,
	"onwheel":      true,
	"ontouchcancel": true,
	"ontouchend":   true,
	"ontouchmove":  true,
	"ontouchstart": true,
	"onanimationend": true,
	"onanimationiteration": true,
	"onanimationstart": true,
	"ontransitionend": true,
	"onauxclick": true,
}

// urlAttrs is a list of attributes that contain URLs
var urlAttrs = map[string]bool{
	"href":   true,
	"src":    true,
	"action": true,
	"formaction": true,
	"data":   true,
	"poster": true,
	"cite":   true,
}

// styleAttrs is a list of style-related attributes
var styleAttrs = map[string]bool{
	"style": true,
}

// Analyze analyzes the response to detect XSS contexts
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	gr := options.FuzzGenerated
	payload := gr.OriginalPayload

	if payload == "" {
		return false, "", nil
	}

	// Rebuild the request to get the current state
	rebuilt, err := gr.Component.Rebuild()
	if err != nil {
		return false, "", err
	}

	// Send the request and get the response
	resp, err := options.HttpClient.Do(rebuilt)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	// Read the response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", err
	}
	body := string(bodyBytes)

	// Check for javascript: URI in the response
	if a.containsJavaScriptURI(body, payload) {
		return true, string(ContextTypeJavaScriptURI), nil
	}

	// Check for srcdoc attribute in the response
	if a.containsSrcdoc(body, payload) {
		return true, string(ContextTypeSrcDoc), nil
	}

	// Parse the HTML and analyze contexts
	contextType := a.analyzeHTMLContext(body, payload)
	if contextType != ContextTypeNone {
		return true, string(contextType), nil
	}

	return false, "", nil
}

// containsJavaScriptURI checks if the payload is in a javascript: URI
func (a *Analyzer) containsJavaScriptURI(body, payload string) bool {
	// Find all occurrences of the payload in the body
	idx := 0
	for {
		i := strings.Index(body[idx:], payload)
		if i == -1 {
			break
		}
		pos := idx + i

		// Get surrounding context (look back for "javascript:")
		start := pos - 20
		if start < 0 {
			start = 0
		}
		prefix := body[start:pos]

		// Check if there's a javascript: URI before the payload
		if javascriptURIRegex.MatchString(prefix) {
			return true
		}

		idx = pos + len(payload)
	}

	return false
}

// containsSrcdoc checks if the payload is in a srcdoc attribute
func (a *Analyzer) containsSrcdoc(body, payload string) bool {
	// Simple check: look for srcdoc= before the payload
	idx := 0
	for {
		i := strings.Index(body[idx:], payload)
		if i == -1 {
			break
		}
		pos := idx + i

		// Get surrounding context (look back for "srcdoc")
		start := pos - 30
		if start < 0 {
			start = 0
		}
		prefix := body[start:pos]

		// Check if there's a srcdoc attribute before the payload
		if srcdocAttrRegex.MatchString(prefix) {
			return true
		}

		idx = pos + len(payload)
	}

	return false
}

// analyzeHTMLContext analyzes the HTML context where the payload appears
func (a *Analyzer) analyzeHTMLContext(body, payload string) ContextType {
	// Parse the HTML document
	doc, err := htmlquery.Parse(strings.NewReader(body))
	if err != nil {
		return ContextTypeNone
	}

	// Find the payload in the document
	var analyzeNode func(n *html.Node) ContextType
	analyzeNode = func(n *html.Node) ContextType {
		// Check if this is a text node containing the payload
		if n.Type == html.TextNode {
			text := n.Data
			if strings.Contains(text, payload) {
				// Check parent element context
				if n.Parent != nil {
					return a.getContextFromParent(n.Parent)
				}
			}
		}

		// Check attributes containing the payload
		for _, attr := range n.Attr {
			if strings.Contains(attr.Val, payload) {
				if eventHandlerAttrs[strings.ToLower(attr.Key)] {
					return ContextTypeEventHandler
				}
				if urlAttrs[strings.ToLower(attr.Key)] {
					// Check if it's a javascript: URI
					if strings.HasPrefix(strings.ToLower(attr.Val), "javascript:") {
						return ContextTypeJavaScriptURI
					}
					return ContextTypeURL
				}
				if styleAttrs[strings.ToLower(attr.Key)] {
					return ContextTypeStyle
				}
				// Check for srcdoc
				if strings.ToLower(attr.Key) == "srcdoc" {
					return ContextTypeSrcDoc
				}
				return ContextTypeHTMLAttribute
			}
		}

		// Check child nodes
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if result := analyzeNode(c); result != ContextTypeNone {
				return result
			}
		}

		return ContextTypeNone
	}

	return analyzeNode(doc)
}

// getContextFromParent determines the XSS context based on the parent element
func (a *Analyzer) getContextFromParent(n *html.Node) ContextType {
	if n.Type != html.ElementNode {
		return ContextTypeHTMLContent
	}

	tagName := strings.ToLower(atom.String(n.Data))

	// Script elements are in JavaScript context
	if tagName == "script" {
		return ContextTypeJavaScript
	}

	// Style elements and style attributes are in CSS context
	if tagName == "style" {
		return ContextTypeStyle
	}

	// Check for event handler attributes
	for _, attr := range n.Attr {
		if eventHandlerAttrs[strings.ToLower(attr.Key)] {
			return ContextTypeEventHandler
		}
	}

	// Check for URL attributes
	for _, attr := range n.Attr {
		if urlAttrs[strings.ToLower(attr.Key)] {
			// Check for javascript: URI
			lowerVal := strings.ToLower(attr.Val)
			if strings.HasPrefix(lowerVal, "javascript:") || strings.HasPrefix(lowerVal, "vbscript:") || strings.HasPrefix(lowerVal, "data:") {
				return ContextTypeJavaScriptURI
			}
			return ContextTypeURL
		}
	}

	// Check for srcdoc
	for _, attr := range n.Attr {
		if strings.ToLower(attr.Key) == "srcdoc" {
			return ContextTypeSrcDoc
		}
	}

	// Check for style attribute
	for _, attr := range n.Attr {
		if strings.ToLower(attr.Key) == "style" {
			return ContextTypeStyle
		}
	}

	// Check if inside SVG or MathML which has special parsing rules
	if tagName == "svg" || tagName == "math" {
		return ContextTypeHTMLContent
	}

	return ContextTypeHTMLContent
}

// Helper function to check if a request has a response
func hasResponse(gr fuzz.GeneratedRequest) bool {
	return gr.Response != nil
}
