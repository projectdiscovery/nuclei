package normalizer

import (
	"strings"

	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/html"
)

// DefaultDOMTransformations is default list of CSS selectors to remove from the DOM.
var DefaultDOMTransformations = []string{
	"style, script, path",           // remove script and style tags
	"input[type='hidden']",          // remove hidden inputs
	"meta[content]",                 // remove meta tags with content
	"link[rel='stylesheet']",        // remove stylesheet links
	"svg",                           // remove svg
	"grammarly-desktop-integration", // remove grammarly
	"div[class*='ad'], div[id*='ad'], div[class*='banner'], div[id*='banner'], div[class*='pixel'], div[id*='pixel']", // remove ad, banner and pixel divs
	"input[name*='csrf'], input[name*='token']", // remove csrf and token inputs
}

// NoChildrenDomTransformations removes all elements with no children
var NoChildrenDomTransformations = []string{
	"div",  // remove divs with no children
	"span", // remove spans with no children
}

// DOMNormalizer is a normalizer for DOM content
type DOMNormalizer struct {
	customTransformations []domTransformationFunc
}

// NewDOMNormalizer returns a new DOMNormalizer
//
// transformations is a list of CSS selectors to remove from the DOM.
func NewDOMNormalizer(transformations []string) *DOMNormalizer {
	var customTransformations []domTransformationFunc
	for _, t := range transformations {
		t := t
		customTransformations = append(customTransformations, func(doc *goquery.Document) {
			doc.Find(t).Each(func(_ int, s *goquery.Selection) {
				s.Remove()
			})
		})
	}
	for _, t := range DefaultDOMTransformations {
		t := t
		customTransformations = append(customTransformations, func(doc *goquery.Document) {
			doc.Find(t).Each(func(_ int, s *goquery.Selection) {
				s.Remove()
			})
		})
	}
	for _, t := range NoChildrenDomTransformations {
		t := t
		customTransformations = append(customTransformations, func(doc *goquery.Document) {
			doc.Find(t).Each(func(_ int, s *goquery.Selection) {
				if s.Children().Length() == 0 && strings.TrimSpace(s.Text()) == "" {
					s.Remove()
				}
			})
		})
	}
	return &DOMNormalizer{customTransformations: customTransformations}
}

// Apply applies the normalizers to the given content
func (d *DOMNormalizer) Apply(content string) (string, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(content))
	if err != nil {
		return "", err
	}
	// Apply selection based transformations
	doc.Find("*").Each(func(_ int, s *goquery.Selection) {
		for _, f := range selectionBasedTransformationFuncs {
			f(s)
		}
	})
	// Apply custom transformations
	for _, f := range d.customTransformations {
		f(doc)
	}
	result, err := doc.Html()
	if err != nil {
		return "", err
	}
	return result, nil
}

// domTransformationFunc does required transformation on document.
type domTransformationFunc func(doc *goquery.Document)

type selectionTransformationFunc func(s *goquery.Selection)

var selectionBasedTransformationFuncs = []selectionTransformationFunc{
	removeCommentsDomTransformationFunc,              // remove comments
	removeClassIDDataAttributesDomTransformationFunc, // remove class, id and data attributes
}

func removeComments(n *html.Node) {
	if n.Type == html.CommentNode {
		n.Parent.RemoveChild(n)
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		removeComments(c)
	}
}

func removeCommentsDomTransformationFunc(s *goquery.Selection) {
	removeComments(s.Get(0))
}

var attributes = []string{
	"class",
	"id",
	"style",
	"width",
	"height",
	"src",
	"nowrap",
	"target",
	"valign",
	"cellpadding",
	"cellspacing",
}

func removeClassIDDataAttributesDomTransformationFunc(s *goquery.Selection) {
	removeAttributes(s)

	// Handle children
	s.Children().Each(func(_ int, child *goquery.Selection) {
		removeClassIDDataAttributesDomTransformationFunc(child)
	})
}

func removeAttributes(s *goquery.Selection) {
	for _, attr := range attributes {
		s.RemoveAttr(attr)
	}

	for _, node := range s.Nodes {
		for _, attr := range node.Attr {
			attr := attr
			if strings.HasPrefix(attr.Key, "data-") || strings.HasPrefix(attr.Key, "aria-") || strings.HasPrefix(attr.Key, "js") {
				s.RemoveAttr(attr.Key)
			}
		}
	}
}
