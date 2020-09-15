package http

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/quarks/matchers"
)

// Request is a http request structure parsed from a yaml file
type Request struct {
	// Matchers contains the detection mechanism for the request to identify
	// whether the request was successful
	Matchers []matchers.Matcher `yaml:"matchers"`
	// Extractors contains the extraction mechanism for the request to identify
	// and extract parts of the response.
	Extractors []extractors.Extractor `yaml:"extractors"`
}
