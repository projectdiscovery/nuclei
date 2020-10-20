package templates

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/requests"
)

// Template is a request template parsed from a yaml file
type Template struct {
	// ID is the unique id for the template
	ID string `yaml:"id"`
	// Info contains information about the template
	Info map[string]string `yaml:"info"`
	// BulkRequestsHTTP contains the http request to make in the template
	BulkRequestsHTTP []*requests.BulkHTTPRequest `yaml:"requests,omitempty"`
	// RequestsDNS contains the dns request to make in the template
	RequestsDNS []*requests.DNSRequest `yaml:"dns,omitempty"`
	path        string
}

// GetPath of the workflow
func (t *Template) GetPath() string {
	return t.path
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
