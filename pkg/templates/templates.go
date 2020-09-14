package templates

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/requests"
)

// Template is a request template parsed from a yaml file
type Template struct {
	// ID is the unique id for the template
	ID string `yaml:"id"`
	// Info contains information about the template
	Info Info `yaml:"info"`

	// HTTPRequests contains the http requests to make in the template
	HTTPRequests []requests.BulkHTTPRequest `yaml:"requests,omitempty"`
	// DNSRequests contains the dns requests to make in the template
	DNSRequests []requests.DNSRequest `yaml:"dns,omitempty"`

	path string
}

// GetPath of the workflow
func (t *Template) GetPath() string {
	return t.path
}

// Info contains information about the request template
type Info struct {
	// Name is the name of the template
	Name string `yaml:"name"`
	// Author is the name of the author of the template
	Author string `yaml:"author"`
	// Severity optionally describes the severity of the template
	Severity string `yaml:"severity,omitempty"`
	// Description optionally describes the template.
	Description string `yaml:"description,omitempty"`
}

func (t *Template) GetHTTPRequestCount() int64 {
	var count int64 = 0
	for _, request := range t.BulkRequestsHTTP {
		count += request.GetRequestCount()
	}

	return count
}

func (t *Template) GetDNSRequestCount() int64 {
	var count int64 = 0
	for _, request := range t.RequestsDNS {
		count += request.GetRequestCount()
	}

	return count
}
