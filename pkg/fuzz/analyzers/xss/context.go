package xss

import (
	"bytes"
	"regexp"
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
	ca.doc.Find("*")
		.EachWithBreak(func(i int, s *goquery.Selection) bool {
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
	// Check for non-executable script types (case-insensitive)
	typeAttr = strings.ToLower(typeAttr)
	return typeAttr == "application/json" || typeAttr == "text/json" ||
		typeAttr == "application/ld+json" || strings.HasPrefix(typeAttr, "application/") ||
		strings.HasPrefix(typeAttr, "text/") && !strings.Contains(typeAttr, "javascript")
}

func (ca *ContextAnalyzer) checkAttributes(s *goquery.Selection) bool {
	node := s.Get(0)
	if node == nil {
		return false
	}

	for _, attr := range node.Attr {
		if ca.containsReflection(attr.Val) {
			ca.attribute = attr.Key
			
			// Special handling for javascript: URIs
			if ca.isJavaScriptURI(attr.Val) {
				ca.context = ContextScript
				return true
			}
			
			// Special handling for srcdoc attribute
			if strings.EqualFold(attr.Key, "srcdoc") {
				ca.context = ContextHTML
				return true
			}
			
			// Check for event handlers
			if strings.HasPrefix(attr.Key, "on") && len(attr.Key) > 2 {
				ca.context = ContextScript
				return true
			}
			
			// Default to attribute context
			ca.context = ContextAttribute
			return true
		}
	}
	return false
}

func (ca *ContextAnalyzer) isJavaScriptURI(value string) bool {
	// Case-insensitive check for javascript: URI
	lowerValue := strings.ToLower(strings.TrimSpace(value))
	return strings.HasPrefix(lowerValue, "javascript:")
}

func (ca *ContextAnalyzer) containsReflection(text string) bool {
	// Case-insensitive check for reflection
	return strings.Contains(strings.ToLower(text), strings.ToLower(ca.reflection))
}

// IsReflected checks if the reflection appears in the HTML document.
func IsReflected(reflection string, body []byte) bool {
	// Case-insensitive check
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
