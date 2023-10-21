package normalizer

import (
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

var DefaultNormalizer *Normalizer

func init() {
	var err error
	DefaultNormalizer, err = New(nil, nil)
	if err != nil {
		panic(fmt.Sprintf("could not create default normalizer: %s", err))
	}
}

// Normalizer is a normalizer for text and DOM content
type Normalizer struct {
	dom  *DOMNormalizer
	text *TextNormalizer
}

// New returns a new Normalizer
//
// textPatterns is a list of regex patterns to remove from the text.
// domSelectors is a list of CSS selectors to remove from the DOM.
func New(textPatterns, domSelectors []string) (*Normalizer, error) {
	textNormalizer, err := NewTextNormalizer(textPatterns)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create text normalizer")
	}
	domNormalizer := NewDOMNormalizer(domSelectors)
	return &Normalizer{
		dom:  domNormalizer,
		text: textNormalizer,
	}, nil
}

// Apply applies the normalizers to the given content
//
// It normalizes the given content by:
// - Applying the DOM normalizer
// - Applying the text normalizer
// - Denormalizing it
func (n *Normalizer) Apply(text string) (string, error) {
	first := normalizeDocument(text)

	firstpass, err := n.dom.Apply(first)
	if err != nil {
		return "", errors.Wrap(err, "failed to apply DOM normalizer")
	}
	secondpass := n.text.Apply(firstpass)

	thirdpass := normalizeDocument(secondpass)
	return thirdpass, nil
}

// normalizeDocument normalizes the given document by:
// - Lowercasing it
// - URL decoding it
// - HTML entity decoding it
// - Replacing all whitespace variations with a space
// - Trimming the document whitespaces
func normalizeDocument(text string) string {
	// Lowercase the document
	lowercased := strings.ToLower(text)

	// Convert hexadecimal escape sequences to HTML entities
	converted := convertHexEscapeSequencesToEntities(lowercased)
	unescaped := html.UnescapeString(converted)

	// URL Decode and HTML entity decode the document to standardize it.
	urlDecoded, err := url.QueryUnescape(unescaped)
	if err != nil {
		urlDecoded = unescaped
	}

	// Trim the document to remove leading and trailing whitespaces
	return strings.Trim(urlDecoded, " \r\n\t")
}

func replaceHexEscapeSequence(match string) string {
	// Remove the '\x' prefix
	code := strings.TrimPrefix(match, "\\x")
	// Parse the hexadecimal code to an integer
	value, err := strconv.ParseInt(code, 16, 32)
	if err != nil {
		// If there's an error, return the original match
		return match
	}
	// Return the corresponding HTML entity
	return fmt.Sprintf("&#x%x;", value)
}

// Define the regex pattern to match hexadecimal escape sequences
var pattern = regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)

func convertHexEscapeSequencesToEntities(input string) string {
	return pattern.ReplaceAllStringFunc(input, func(match string) string {
		return replaceHexEscapeSequence(match)
	})
}
