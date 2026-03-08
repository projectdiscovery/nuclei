package xss

import (
	"bytes"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/projectdiscovery/gologger"
	"golang.org/x/net/html"
)

// Context represents the context in which a reflection occurs
// within an HTML document.
type Context int

const (
	ContextUnknown Context = iota
	ContextText
	ContextAttribute
	ContextScript
	ContextHTML
)

// ContextAnalyzer analyzes the context of a reflection in an HTML document.
type ContextAnalyzer struct {
	reflection string
	doc        *goquery.Document
	context    Context
	attribute  string
}

// NewContextAnalyzer creates a new context analyzer for the given reflection.
func NewContextAnalyzer(reflection string, doc *goquery.Document) *ContextAnalyzer {
	return &ContextAnalyzer{
		reflection: reflection,
		doc:        doc,
		context:    ContextUnknown,
	}
}

// Analyze analyzes the context of the reflection in the HTML document.
func (ca *ContextAnalyzer) Analyze() (Context, string) {
	ca.analyzeDocument()
	return ca.context, ca.attribute
}

func (ca *ContextAnalyzer) analyzeDocument() {
	ca.doc.Find("*").EachWithBreak(func(i int, s *goquery.Selection) bool {
		if ca.context != ContextUnknown {
			return false
		}

		// Check text nodes
		if ca.checkTextNodes(s) {
			return false
		}

		// Check attributes
		if ca.checkAttributes(s) {
			return false
		}

		return true
	})
}

func (ca *ContextAnalyzer) checkTextNodes(s *goquery.Selection) bool {
	// Get the raw HTML node
	node := s.Get(0)
	if node == nil {
		return false
	}

	// Check text nodes
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if child.Type == html.TextNode {
			if ca.containsReflection(child.Data) {
				// Check if we're inside a script tag
				if node.Data == "script" {
					// Check for non-executable script types
					if ca.isNonExecutableScript(s) {
						ca.context = ContextText
					} else {
						ca.context = ContextScript
					}
				} else {
					ca.context = ContextText
				}
				return true
			}
		}
	}
	return false
}

func (ca *ContextAnalyzer) isNonExecutableScript(s *goquery.Selection) bool {
	typeAttr, exists := s.Attr("type")
	if !exists {
		return false
	}
	typeAttr = strings.ToLower(typeAttr)
	// Executable script types
	if strings.Contains(typeAttr, "javascript") || strings.Contains(typeAttr, "ecmascript") {
		return false
	}
	// ES6 modules are executable
	if typeAttr == "module" {
		return false
	}
	// Non-executable data types
	return typeAttr == "application/json" || typeAttr == "text/json" ||
		typeAttr == "application/ld+json" || typeAttr == "text/plain" ||
		typeAttr == "text/html" || typeAttr == "text/xml"
}

func (ca *ContextAnalyzer) checkAttributes(s *goquery.Selection) bool {
	node := s.Get(0)
	if node == nil {
		return false
	}

	for _, attr := range node.Attr {
		if ca.containsReflection(attr.Val) {
			ca.attribute = attr.Key

			// Special handling for javascript:, vbscript:, and data: URIs
			if ca.isExecutableURI(attr.Val) {
				ca.context = ContextScript
				return true
			}

			// Special handling for srcdoc attribute
			if strings.EqualFold(attr.Key, "srcdoc") {
				ca.context = ContextHTML
				return true
			}

			// Check for event handlers (case-insensitive)
			lowerKey := strings.ToLower(attr.Key)
			if strings.HasPrefix(lowerKey, "on") && len(lowerKey) > 2 {
				ca.context = ContextScript
				return true
			}

			// Check formaction attribute for executable URIs
			if strings.EqualFold(attr.Key, "formaction") {
				if ca.isExecutableURI(attr.Val) {
					ca.context = ContextScript
					return true
				}
			}

			// Default to attribute context
			ca.context = ContextAttribute
			return true
		}
	}
	return false
}

// isExecutableURI checks for executable URI schemes including javascript:,
// vbscript: (legacy IE), and data: URIs which can execute code.
func (ca *ContextAnalyzer) isExecutableURI(value string) bool {
	lowerValue := strings.ToLower(strings.TrimSpace(value))
	return strings.HasPrefix(lowerValue, "javascript:") ||
		strings.HasPrefix(lowerValue, "vbscript:") ||
		strings.HasPrefix(lowerValue, "data:")
}

// isJavaScriptURI is kept for backward compatibility.
func (ca *ContextAnalyzer) isJavaScriptURI(value string) bool {
	return ca.isExecutableURI(value)
}

func (ca *ContextAnalyzer) containsReflection(text string) bool {
	return strings.Contains(strings.ToLower(text), strings.ToLower(ca.reflection))
}

// IsReflected checks if the reflection appears in the HTML document.
func IsReflected(reflection string, body []byte) bool {
	return bytes.Contains(bytes.ToLower(body), bytes.ToLower([]byte(reflection)))
}

// AnalyzeContext analyzes the context of a reflection in an HTML document.
func AnalyzeContext(reflection string, body []byte) (Context, string, error) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		gologger.Debug().Msgf("Failed to parse HTML for context analysis: %s", err)
		return ContextUnknown, "", err
	}

	analyzer := NewContextAnalyzer(reflection, doc)
	context, attribute := analyzer.Analyze()
	return context, attribute, nil
}
