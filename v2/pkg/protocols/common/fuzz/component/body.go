package component

import (
	"io"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/fuzz/dataformat"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/fuzz/encoding"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Body is a component for a request body
type Body struct {
	parsed          string
	decoded         map[string]interface{}
	encodingDecoded *encoding.Decoded
	decoder         string
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

	// Do any decoding on the data if needed
	decoded, err := encoding.Decode(b.parsed)
	if err == nil {
		b.encodingDecoded = decoded
		b.parsed = decoded.Data
	}

	switch {
	case strings.Contains(contentType, "application/x-www-form-urlencoded"):
		return b.parseBody("form", req)
	case strings.Contains(contentType, "application/json") || dataformat.Get("json").IsType(b.parsed):
		return b.parseBody("json", req)
	case strings.Contains(contentType, "application/xml") || dataformat.Get("xml").IsType(b.parsed):
		return b.parseBody("xml", req)
		// case strings.Contains(contentType, "multipart/form-data"):
		// 	return b.parseMultipart(req)
	}
	return b.parseBody("raw", req)
}

// parseBody parses a body with a custom decoder
func (b *Body) parseBody(decoderName string, req *retryablehttp.Request) error {
	decoder := dataformat.Get(decoderName)
	decoded, err := decoder.Decode(b.parsed)
	if err != nil {
		return errors.Wrap(err, "could not decode raw")
	}
	b.decoded = decoded
	b.decoder = decoder.Name()
	return nil
}

// Iterate iterates through the component
func (b *Body) Iterate(callback func(key string, value interface{})) {
	// We cannot iterate normally because there
	// can be multiple nesting. So we need to a do traversal
	// and get keys with values that can be assigned values dynamically.

}

// SetValue sets a value in the component
func (b *Body) SetValue(key string, value string) error {

	return nil
}

// Rebuild returns a new request with the
// component rebuilt
func (b *Body) Rebuild() (*retryablehttp.Request, error) {
	// When rebuilding, account for any encodings applied
	// to the body.
	return nil, nil
}
