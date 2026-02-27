package xss

import (
	"strings"

	"golang.org/x/net/html"
)

// urlAttributes lists attribute names that accept URL values.
var urlAttributes = map[string]bool{
	"href":       true,
	"src":        true,
	"action":     true,
	"formaction": true,
	"data":       true,
	"poster":     true,
	"codebase":   true,
	"cite":       true,
	"background": true,
	"ping":       true,
	"icon":       true,
	"manifest":   true,
}

// reflectionPoint represents a single location where the canary appears in the response.
type reflectionPoint struct {
	Context XSSContext
}

// findReflections tokenizes the HTML body and returns all contexts where the canary is reflected.
// It uses golang.org/x/net/html for HTML-level context detection, then delegates to
// gotreesitter-based JS and CSS parsers for sub-context classification.
func findReflections(body []byte, canary string) []reflectionPoint {
	var points []reflectionPoint
	bodyStr := string(body)

	// Quick check
	if !strings.Contains(bodyStr, canary) {
		return nil
	}

	tokenizer := html.NewTokenizer(strings.NewReader(bodyStr))

	// Track current element context for raw text
	var currentTag string
	var currentAttrs []html.Attribute

	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}

		switch tt {
		case html.TextToken:
			text := string(tokenizer.Text())
			if !strings.Contains(text, canary) {
				continue
			}

			switch currentTag {
			case "script":
				ctx := classifyJSContext([]byte(text), canary, 0)
				points = append(points, reflectionPoint{Context: ctx})
			case "style":
				ctx := classifyCSSContext([]byte(text), canary)
				points = append(points, reflectionPoint{Context: ctx})
			default:
				points = append(points, reflectionPoint{Context: ContextHTMLText})
			}

		case html.StartTagToken:
			tn, hasAttr := tokenizer.TagName()
			currentTag = string(tn)
			if hasAttr {
				currentAttrs = collectAttrs(tokenizer)
			} else {
				currentAttrs = nil
			}

			// Check attributes for canary
			for _, attr := range currentAttrs {
				if !strings.Contains(attr.Val, canary) {
					continue
				}
				ctx := classifyAttribute(attr, bodyStr)
				points = append(points, reflectionPoint{Context: ctx})
			}

		case html.SelfClosingTagToken:
			tn, hasAttr := tokenizer.TagName()
			currentTag = string(tn)
			if hasAttr {
				currentAttrs = collectAttrs(tokenizer)
			} else {
				currentAttrs = nil
			}

			for _, attr := range currentAttrs {
				if !strings.Contains(attr.Val, canary) {
					continue
				}
				ctx := classifyAttribute(attr, bodyStr)
				points = append(points, reflectionPoint{Context: ctx})
			}
			currentTag = ""

		case html.EndTagToken:
			currentTag = ""

		case html.CommentToken:
			text := string(tokenizer.Text())
			if strings.Contains(text, canary) {
				points = append(points, reflectionPoint{Context: ContextHTMLComment})
			}
		}
	}

	return points
}

// collectAttrs reads all attributes from the current tag token.
func collectAttrs(tokenizer *html.Tokenizer) []html.Attribute {
	var attrs []html.Attribute
	for {
		key, val, more := tokenizer.TagAttr()
		attrs = append(attrs, html.Attribute{
			Key: string(key),
			Val: string(val),
		})
		if !more {
			break
		}
	}
	return attrs
}

// classifyAttribute determines the XSS context of a canary reflected in an attribute value.
func classifyAttribute(attr html.Attribute, bodyStr string) XSSContext {
	name := strings.ToLower(attr.Key)

	// Event handlers (onclick, onload, onerror, etc.)
	if strings.HasPrefix(name, "on") && len(name) > 2 {
		return ContextEventHandler
	}

	// URL attributes
	if urlAttributes[name] {
		return ContextURLAttribute
	}

	// Style attribute
	if name == "style" {
		return ContextStyleAttribute
	}

	// Determine quote type by searching for the attribute in the raw HTML
	quoteCtx := findQuoteContext(attr, bodyStr)
	return quoteCtx
}

// findQuoteContext determines the quoting style of an attribute value by inspecting
// the raw HTML around the attribute assignment.
func findQuoteContext(attr html.Attribute, bodyStr string) XSSContext {
	// Search for key= followed by quote character or raw value in the original HTML.
	// We search case-insensitively for the attribute name, then check what follows '='.
	lower := strings.ToLower(bodyStr)
	key := strings.ToLower(attr.Key)
	searchFrom := 0
	for {
		idx := strings.Index(lower[searchFrom:], key+"=")
		if idx < 0 {
			break
		}
		pos := searchFrom + idx + len(key) + 1 // position after '='
		if pos >= len(bodyStr) {
			break
		}
		ch := bodyStr[pos]
		switch ch {
		case '"':
			return ContextAttrValueDoubleQuoted
		case '\'':
			return ContextAttrValueSingleQuoted
		default:
			// Verify this is actually our attribute value (not some random substring)
			valEnd := strings.IndexAny(bodyStr[pos:], " \t\n\r>")
			if valEnd < 0 {
				valEnd = len(bodyStr) - pos
			}
			rawVal := bodyStr[pos : pos+valEnd]
			if strings.Contains(rawVal, attr.Val) {
				return ContextAttrValueUnquoted
			}
		}
		searchFrom = pos
	}

	return ContextAttrValueDoubleQuoted
}
