package utils

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	iputil "github.com/projectdiscovery/utils/ip"
	urlutil "github.com/projectdiscovery/utils/url"
)

// JsonFields contains additional metadata fields for JSON output
type JsonFields struct {
	Host   string `json:"host,omitempty"`
	Path   string `json:"path,omitempty"`
	Port   string `json:"port,omitempty"`
	Ip     string `json:"ip,omitempty"`
	Scheme string `json:"scheme,omitempty"`
	URL    string `json:"url,omitempty"`
}

// GetJsonFields returns the json fields for the request
func GetJsonFieldsFromURL(URL string) JsonFields {
	parsed, err := urlutil.Parse(URL)
	if err != nil {
		return JsonFields{}
	}
	fields := JsonFields{
		Port:   parsed.Port(),
		Scheme: parsed.Scheme,
		URL:    parsed.String(),
		Path:   parsed.Path,
	}
	if fields.Port == "" {
		fields.Port = "80"
		if fields.Scheme == "https" {
			fields.Port = "443"
		}
	}
	if iputil.IsIP(parsed.Host) {
		fields.Ip = parsed.Host
	}

	fields.Host = parsed.Host
	return fields
}

// GetJsonFieldsFromMetaInput returns the json fields for the request
func GetJsonFieldsFromMetaInput(ctx *contextargs.MetaInput) JsonFields {
	input := ctx.Input
	fields := JsonFields{
		Ip: ctx.CustomIP,
	}
	parsed, err := urlutil.Parse(input)
	if err != nil {
		return fields
	}
	fields.Port = parsed.Port()
	fields.Scheme = parsed.Scheme
	fields.URL = parsed.String()
	fields.Path = parsed.Path
	if fields.Port == "" {
		fields.Port = "80"
		if fields.Scheme == "https" {
			fields.Port = "443"
		}
	}
	if iputil.IsIP(parsed.Host) {
		fields.Ip = parsed.Host
	}

	fields.Host = parsed.Host
	return fields
}
