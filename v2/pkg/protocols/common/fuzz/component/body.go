package component

import (
	"io"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/fuzz/dataformat"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Body is a component for a request body
type Body struct {
	parsed  string
	decoded map[string]interface{}
	decoder string
}

var _ Component = &Body{}

// NewBody creates a new body component
func NewBody() *Body {
	return &Body{}
}

// Name returns the name of the component
func (b *Body) Name() string {
	return "body"
}

// Parse parses the component and returns the
// parsed component
func (b *Body) Parse(req *retryablehttp.Request) error {
	if req.Body == nil {
		return nil
	}
	contentType := req.Header.Get("Content-Type")

	data, err := io.ReadAll(req.Body)
	if err != nil {
		return errors.Wrap(err, "could not read body")
	}
	b.parsed = string(data)

	switch {
	case strings.Contains(contentType, "application/x-www-form-urlencoded"):
		return b.parseForm(req)
	case strings.Contains(contentType, "application/json") || dataformat.Get("json").IsType(b.parsed):
		return b.parseJSON(req)
	case strings.Contains(contentType, "application/xml") || dataformat.Get("xml").IsType(b.parsed):
		return b.parseXML(req)
		// case strings.Contains(contentType, "multipart/form-data"):
		// 	return b.parseMultipart(req)
	}

	return nil
}

// parseForm parses a form body
func (b *Body) parseForm(req *retryablehttp.Request) error {
	decoder := dataformat.Get("form")
	decoded, err := decoder.Decode(b.parsed)
	if err != nil {
		return errors.Wrap(err, "could not decode form")
	}
	b.decoded = decoded
	b.decoder = decoder.Name()
	return nil
}

// parseJSON parses a json body
func (b *Body) parseJSON(req *retryablehttp.Request) error {
	decoder := dataformat.Get("json")
	decoded, err := decoder.Decode(b.parsed)
	if err != nil {
		return errors.Wrap(err, "could not decode json")
	}
	b.decoded = decoded
	b.decoder = decoder.Name()
	return nil
}

// parseXML parses a xml body
func (b *Body) parseXML(req *retryablehttp.Request) error {
	decoder := dataformat.Get("xml")
	decoded, err := decoder.Decode(b.parsed)
	if err != nil {
		return errors.Wrap(err, "could not decode xml")
	}
	b.decoded = decoded
	b.decoder = decoder.Name()
	return nil
}

// Iterate iterates through the component
func (b *Body) Iterate(callback func(key string, value interface{})) {
	for key, value := range b.decoded {
		callback(key, value)
	}
}

// SetValue sets a value in the component
func (b *Body) SetValue(key string, value string) error {
	return nil
}

// Rebuild returns a new request with the
// component rebuilt
func (b *Body) Rebuild() (*retryablehttp.Request, error) {
	return nil, nil
}
