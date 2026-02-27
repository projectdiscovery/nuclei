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
				ctx := classifyJSContext([]byte(text), canary)
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
	lower := strings.ToLower(bodyStr)
	key := strings.ToLower(attr.Key)
	searchFrom := 0
	for searchFrom < len(lower) {
		idx := strings.Index(lower[searchFrom:], key)
		if idx < 0 {
			break
		}

		keyStart := searchFrom + idx
		keyEnd := keyStart + len(key)

		// Match whole attribute names only.
		if keyStart > 0 && isAttrIdentifierChar(lower[keyStart-1]) {
			searchFrom = keyEnd
			continue
		}
		if keyEnd < len(lower) && isAttrIdentifierChar(lower[keyEnd]) {
			searchFrom = keyEnd
			continue
		}

		pos := keyEnd
		for pos < len(bodyStr) && isHTMLSpace(bodyStr[pos]) {
			pos++
		}
		if pos >= len(bodyStr) || bodyStr[pos] != '=' {
			searchFrom = keyEnd
			continue
		}
		pos++ // position after '='
		for pos < len(bodyStr) && isHTMLSpace(bodyStr[pos]) {
			pos++
		}
		if pos >= len(bodyStr) {
			break
		}

		valueEnd := pos
		switch bodyStr[pos] {
		case '"':
			valueStart := pos + 1
			endRel := strings.IndexByte(bodyStr[valueStart:], '"')
			rawVal := bodyStr[valueStart:]
			valueEnd = len(bodyStr)
			if endRel >= 0 {
				valueEnd = valueStart + endRel + 1
				rawVal = bodyStr[valueStart : valueEnd-1]
			}
			if strings.Contains(rawVal, attr.Val) {
				return ContextAttrValueDoubleQuoted
			}
		case '\'':
			valueStart := pos + 1
			endRel := strings.IndexByte(bodyStr[valueStart:], '\'')
			rawVal := bodyStr[valueStart:]
			valueEnd = len(bodyStr)
			if endRel >= 0 {
				valueEnd = valueStart + endRel + 1
				rawVal = bodyStr[valueStart : valueEnd-1]
			}
			if strings.Contains(rawVal, attr.Val) {
				return ContextAttrValueSingleQuoted
			}
		default:
			valEnd := strings.IndexAny(bodyStr[pos:], " \t\n\r>")
			if valEnd < 0 {
				valueEnd = len(bodyStr)
			} else {
				valueEnd = pos + valEnd
			}
			rawVal := bodyStr[pos:valueEnd]
			if strings.Contains(rawVal, attr.Val) {
				return ContextAttrValueUnquoted
			}
		}

		if valueEnd <= pos {
			searchFrom = pos + 1
			continue
		}
		searchFrom = valueEnd
	}

	return ContextAttrValueDoubleQuoted
}

// isAttrIdentifierChar reports whether ch can appear in an HTML attribute name.
func isAttrIdentifierChar(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') ||
		(ch >= '0' && ch <= '9') ||
		ch == '-' ||
		ch == '_' ||
		ch == ':'
}

// isHTMLSpace reports whether ch is HTML attribute-list whitespace.
func isHTMLSpace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\f'
}
