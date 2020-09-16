package dns

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/post/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/post/matchers"
)

// Request is a dns request structure parsed from a yaml file
type Request struct {
	Recursion bool `yaml:"recursion"`
	// Path contains the path/s for the request
	Name    string `yaml:"name"`
	Type    string `yaml:"type"`
	Class   string `yaml:"class"`
	Retries int    `yaml:"retries"`

	// Matchers contains the detection mechanism for the request to identify
	// whether the request was successful
	Matchers []*matchers.Matcher `yaml:"matchers"`
	// Extractors contains the extraction mechanism for the request to identify
	// and extract parts of the response.
	Extractors []*extractors.Extractor `yaml:"extractors"`
	// MatchersCondition is the condition of the matchers
	// whether to use AND or OR. Default is OR.
	MatchersCondition string `yaml:"matchers-condition"`
}
