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
	value *Value
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
	dataStr := string(data)

	b.value = NewValue(dataStr)

	switch {
	case strings.Contains(contentType, "application/x-www-form-urlencoded"):
		return b.parseBody("form", req)
	case strings.Contains(contentType, "application/json") && b.value.Parsed() == nil:
		return b.parseBody("json", req)
	case strings.Contains(contentType, "application/xml") && b.value.Parsed() == nil:
		return b.parseBody("xml", req)
		// case strings.Contains(contentType, "multipart/form-data"):
		// 	return b.parseMultipart(req)
	}
	if b.value.Parsed() != nil {
		return nil
	}
	return b.parseBody("raw", req)
}

// parseBody parses a body with a custom decoder
func (b *Body) parseBody(decoderName string, req *retryablehttp.Request) error {
	decoder := dataformat.Get(decoderName)
	decoded, err := decoder.Decode(b.value.String())
	if err != nil {
		return errors.Wrap(err, "could not decode raw")
	}
	b.value.SetParsed(decoded, decoder.Name())
	return nil
}

// Iterate iterates through the component
//
// We cannot iterate normally because there
// can be multiple nesting. So we need to a do traversal
// and get keys with values that can be assigned values dynamically.
// Therefore we flatten the value map and iterate over it.
func (b *Body) Iterate(callback func(key string, value interface{})) {
	for key, value := range b.value.Parsed() {
		callback(key, value)
	}
}

// SetValue sets a value in the component
//
// After calling setValue for mutation, the value must be
// called again so as to reset the body to its original state.
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
