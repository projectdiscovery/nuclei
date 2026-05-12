// Package bodycache memoizes per-response HTML, XML and JSON parses so that
// multiple matchers and extractors against the same response share a single
// parse. Without this, each MatchHTML/MatchXML/ExtractHTML/ExtractXML/ExtractJSON
// call re-parses the body independently, which is a substantial slice of the
// per-response CPU budget for clustered or matcher-heavy templates.
//
// The cache is intentionally tiny: a single most-recent entry per parser
// type. The vast majority of matchers in one operator block target the same
// corpus (typically the response body), so a one-slot LRU achieves near-100%
// hit rate without map allocation or hashing of large body strings.
package bodycache

import (
	"strings"

	"github.com/antchfx/htmlquery"
	"github.com/antchfx/xmlquery"
	"golang.org/x/net/html"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

// Key is the reserved entry on output.InternalEvent / data maps that holds
// a *Cache. Underscored prefix avoids collisions with template variables and
// DSL identifiers.
const Key = "__nuclei_bodycache"

// Cache stores at most one parsed form per parser type. Matchers/extractors
// typically run sequentially against one response on one goroutine, so no
// synchronization is required.
type Cache struct {
	htmlCorpus string
	htmlDoc    *html.Node
	htmlErr    error
	htmlSet    bool

	xmlCorpus string
	xmlDoc    *xmlquery.Node
	xmlErr    error
	xmlSet    bool

	jsonCorpus string
	jsonObj    interface{}
	jsonErr    error
	jsonSet    bool

	loweredCorpus string
	loweredOut    string
	loweredSet    bool
}

// From returns the Cache associated with data, creating one on demand. Calls
// from within Match/Extract dispatch share the same instance for the lifetime
// of a single response event.
func From(data map[string]interface{}) *Cache {
	if data == nil {
		return &Cache{}
	}
	if v, ok := data[Key]; ok {
		if c, ok := v.(*Cache); ok && c != nil {
			return c
		}
	}
	c := &Cache{}
	data[Key] = c
	return c
}

// HTMLNode returns the parsed HTML tree for corpus. Subsequent calls with
// the same corpus return the cached parse; calls with a different corpus
// re-parse and replace the cache entry.
func (c *Cache) HTMLNode(corpus string) (*html.Node, error) {
	if c.htmlSet && c.htmlCorpus == corpus {
		return c.htmlDoc, c.htmlErr
	}
	doc, err := htmlquery.Parse(strings.NewReader(corpus))
	c.htmlCorpus = corpus
	c.htmlDoc = doc
	c.htmlErr = err
	c.htmlSet = true
	return doc, err
}

// XMLNode returns the parsed XML tree for corpus. Same caching contract as
// HTMLNode.
func (c *Cache) XMLNode(corpus string) (*xmlquery.Node, error) {
	if c.xmlSet && c.xmlCorpus == corpus {
		return c.xmlDoc, c.xmlErr
	}
	doc, err := xmlquery.Parse(strings.NewReader(corpus))
	c.xmlCorpus = corpus
	c.xmlDoc = doc
	c.xmlErr = err
	c.xmlSet = true
	return doc, err
}

// JSONObject returns the unmarshaled JSON value for corpus. Same caching
// contract as HTMLNode.
func (c *Cache) JSONObject(corpus string) (interface{}, error) {
	if c.jsonSet && c.jsonCorpus == corpus {
		return c.jsonObj, c.jsonErr
	}
	var obj interface{}
	err := json.Unmarshal([]byte(corpus), &obj)
	c.jsonCorpus = corpus
	c.jsonObj = obj
	c.jsonErr = err
	c.jsonSet = true
	return obj, err
}

// Lowered returns the lower-cased form of corpus. Cached so repeated
// case-insensitive word matchers against the same body avoid redundant
// O(n) ToLower allocations.
func (c *Cache) Lowered(corpus string) string {
	if c.loweredSet && c.loweredCorpus == corpus {
		return c.loweredOut
	}
	out := strings.ToLower(corpus)
	c.loweredCorpus = corpus
	c.loweredOut = out
	c.loweredSet = true
	return out
}
