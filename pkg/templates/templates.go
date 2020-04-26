package templates

import (
	"github.com/projectdiscovery/nuclei/pkg/requests"
)

// Template is a request template parsed from a yaml file
type Template struct {
	// ID is the unique id for the template
	ID string `yaml:"id"`
	// Info contains information about the template
	Info Info `yaml:"info"`
	// RequestHTTP contains the http request to make in the template
	RequestsHTTP []*requests.HTTPRequest `yaml:"requests"`
	// RequestDNS contains the dns request to make in the template
	RequestsDNS []*requests.DNSRequest `yaml:"dns"`
}

// Info contains information about the request template
type Info struct {
	// Name is the name of the template
	Name string `yaml:"name"`
	// Author is the name of the author of the template
	Author string `yaml:"author"`
	// Severity optionally describes the severity of the template
	Severity string `yaml:"severity,omitempty"`
}

// Levels of severity for a request template
const (
	SeverityHigh   = "high"
	SeverityMedium = "medium"
	SeverityLow    = "low"
)
