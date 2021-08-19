package extractors

import (
	"regexp"

	"github.com/itchyny/gojq"
)

// Extractor is used to extract part of response using a regex.
type Extractor struct {
	// description: |
	//   Name of the extractor. Name should be lowercase and must not contain
	//   spaces or dashes (-).
	// examples:
	//   - value: "\"cookie-extractor\""
	Name string `yaml:"name,omitempty"`
	// description: |
	//   Type is the type of the extractor.
	// values:
	//   - "regex"
	//   - "kval"
	Type string `yaml:"type"`
	// extractorType is the internal type of the extractor
	extractorType ExtractorType

	// description: |
	//   Regex contains the regular expression patterns to exract from a part.
	//
	//   Go regex engine does not supports lookaheads or lookbehinds, so as a result
	//   they are also not supported in nuclei.
	// examples:
	//   - name: Braintree Access Token Regex
	//     value: >
	//       []string{"access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}"}
	//   - name: Wordpress Author Extraction regex
	//     value: >
	//       []string{"Author:(?:[A-Za-z0-9 -\\_=\"]+)?<span(?:[A-Za-z0-9 -\\_=\"]+)?>([A-Za-z0-9]+)<\\/span>"}
	Regex []string `yaml:"regex,omitempty"`
	// description: |
	//   Group specifies a numbered group to extract from the regex.
	// examples:
	//   - name: Example Regex Group
	//     value: "1"
	RegexGroup int `yaml:"group,omitempty"`
	// regexCompiled is the compiled variant
	regexCompiled []*regexp.Regexp

	// description: |
	//   kval contains the key-value pairs required in the response.
	//
	//   Each protocol exposes a lot of different data in response. The kval
	//   extractor can be used to extract those key-value pairs. A list of
	//   supported parts is available in docs for request types.
	// examples:
	//   - name: Extract Server Header From HTTP Response
	//     value: >
	//       []string{"Server"}
	//   - name: Extracting value of PHPSESSID Cookie
	//     value: >
	//       []string{"PHPSESSID"}
	KVal []string `yaml:"kval,omitempty"`

	// description: |
	//   Part is the part of the request response to extract data from.
	//
	//   Each protocol exposes a lot of different parts which are well
	//   documented in docs for each request type.
	// examples:
	//   - value: "\"body\""
	//   - value: "\"raw\""
	Part string `yaml:"part,omitempty"`

	// description: |
	//   JSON allows using jq-style syntax to extract items from json response
	//
	// examples:
	//   - value: >
	//       []string{".[] | .id"}
	//   - value: >
	//       []string{".batters | .batter | .[] | .id"}
	JSON []string `yaml:"json,omitempty"`
	// description: |
	//   XPath allows using xpath expressions to extract items from html response
	//
	// examples:
	//   - value: >
	//       []string{"/html/body/div/p[2]/a"}
	//   - value: >
	//       []string{".batters | .batter | .[] | .id"}
	XPath []string `yaml:"xpath,omitempty"`
	// description: |
	//   Attribute is an optional attribute to extract from response XPath.
	//
	// examples:
	//   - value: "\"href\""
	Attribute string `yaml:"attribute,omitempty"`

	// jsonCompiled is the compiled variant
	jsonCompiled []*gojq.Code

	// description: |
	//   Internal, when set to true will allow using the value extracted
	//   in the next request for some protocols (like HTTP).
	Internal bool `yaml:"internal,omitempty"`
}

// ExtractorType is the type of the extractor specified
type ExtractorType = int

const (
	// RegexExtractor extracts responses with regexes
	RegexExtractor ExtractorType = iota + 1
	// KValExtractor extracts responses with key:value
	KValExtractor
	// XPathExtractor extracts responses with Xpath selectors
	XPathExtractor
	// JSONExtractor extracts responses with json
	JSONExtractor
)

// ExtractorTypes is an table for conversion of extractor type from string.
var ExtractorTypes = map[string]ExtractorType{
	"regex": RegexExtractor,
	"kval":  KValExtractor,
	"xpath": XPathExtractor,
	"json":  JSONExtractor,
}

// GetType returns the type of the matcher
func (e *Extractor) GetType() ExtractorType {
	return e.extractorType
}
