package component

import (
	"bytes"
	"context"
	"io"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/dataformat"
	"github.com/projectdiscovery/retryablehttp-go"
	readerutil "github.com/projectdiscovery/utils/reader"
)

// Body is a component for a request body
type Body struct {
	value *Value

	req *retryablehttp.Request
}

var _ Component = &Body{}

// NewBody creates a new body component
func NewBody() *Body {
	return &Body{}
}

// Name returns the name of the component
func (b *Body) Name() string {
	return RequestBodyComponent
}

// Parse parses the component and returns the
// parsed component
func (b *Body) Parse(req *retryablehttp.Request) (bool, error) {
	if req.Body == nil {
		return false, nil
	}
	b.req = req

	contentType := req.Header.Get("Content-Type")

	data, err := io.ReadAll(req.Body)
	if err != nil {
		return false, errors.Wrap(err, "could not read body")
	}
	req.Body = io.NopCloser(bytes.NewReader(data))
	dataStr := string(data)

	if dataStr == "" {
		return false, nil
	}

	b.value = NewValue(dataStr)
	if b.value.Parsed() != nil {
		return true, nil
	}

	switch {
	case strings.Contains(contentType, "application/json") && b.value.Parsed() == nil:
		return b.parseBody(dataformat.JSONDataFormat, req)
	case strings.Contains(contentType, "application/xml") && b.value.Parsed() == nil:
		return b.parseBody(dataformat.XMLDataFormat, req)
	}
	parsed, err := b.parseBody(dataformat.FormDataFormat, req)
	if err != nil {
		gologger.Warning().Msgf("Could not parse body as form data: %s\n", err)
		return b.parseBody(dataformat.RawDataFormat, req)
	}
	return parsed, err
}

// parseBody parses a body with a custom decoder
func (b *Body) parseBody(decoderName string, req *retryablehttp.Request) (bool, error) {
	decoder := dataformat.Get(decoderName)
	decoded, err := decoder.Decode(b.value.String())
	if err != nil {
		return false, errors.Wrap(err, "could not decode raw")
	}
	b.value.SetParsed(decoded, decoder.Name())
	return true, nil
}

// Iterate iterates through the component
func (b *Body) Iterate(callback func(key string, value interface{})) {
	for key, value := range b.value.Parsed() {
		if strings.HasPrefix(key, "#_") {
			continue
		}
		callback(key, value)
	}
}

// SetValue sets a value in the component
func (b *Body) SetValue(key string, value string) error {
	if !b.value.SetParsedValue(key, value) {
		return ErrSetValue
	}
	return nil
}

// Delete deletes a key from the component
func (b *Body) Delete(key string) error {
	if !b.value.Delete(key) {
		return ErrKeyNotFound
	}
	return nil
}

// Rebuild returns a new request with the
// component rebuilt
func (b *Body) Rebuild() (*retryablehttp.Request, error) {
	encoded, err := b.value.Encode()
	if err != nil {
		return nil, errors.Wrap(err, "could not encode body")
	}
	cloned := b.req.Clone(context.Background())
	reusableReader, err := readerutil.NewReusableReadCloser(encoded)
	if err != nil {
		return nil, errors.Wrap(err, "could not create reusable reader")
	}
	cloned.Body = reusableReader
	cloned.ContentLength = int64(len(encoded))
	cloned.Header.Set("Content-Length", strconv.Itoa(len(encoded)))
	return cloned, nil
}
