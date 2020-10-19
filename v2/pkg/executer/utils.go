package executer

import (
	"net/http"
	"net/url"
	"strings"
	"unsafe"
)

type jsonOutput map[string]interface{}

/*
type jsonOutput struct {
	Template         string                 `json:"template"`
	Type             string                 `json:"type"`
	Matched          string                 `json:"matched"`
	MatcherName      string                 `json:"matcher_name,omitempty"`
	ExtractedResults []string               `json:"extracted_results,omitempty"`
	Name             string                 `json:"name"`
	Severity         string                 `json:"severity"`
	Author           string                 `json:"author"`
	Description      string                 `json:"description"`
	Request          string                 `json:"request,omitempty"`
	Response         string                 `json:"response,omitempty"`
	Meta             map[string]interface{} `json:"meta,omitempty"`
}*/

// unsafeToString converts byte slice to string with zero allocations
func unsafeToString(bs []byte) string {
	return *(*string)(unsafe.Pointer(&bs))
}

// headersToString converts http headers to string
func headersToString(headers http.Header) string {
	builder := &strings.Builder{}

	for header, values := range headers {
		builder.WriteString(header)
		builder.WriteString(": ")

		for i, value := range values {
			builder.WriteString(value)

			if i != len(values)-1 {
				builder.WriteRune('\n')
				builder.WriteString(header)
				builder.WriteString(": ")
			}
		}
		builder.WriteRune('\n')
	}
	return builder.String()
}

// isURL tests a string to determine if it is a well-structured url or not.
func isURL(toTest string) bool {
	_, err := url.ParseRequestURI(toTest)
	if err != nil {
		return false
	}
	u, err := url.Parse(toTest)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	return true
}

// extractDomain extracts the domain name of a URL
func extractDomain(theURL string) string {
	u, err := url.Parse(theURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
