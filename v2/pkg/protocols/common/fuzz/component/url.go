package component

import (
	"context"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/fuzz/dataformat"
	"github.com/projectdiscovery/retryablehttp-go"
)

// URL is a component for a request URL
type URL struct {
	value *Value

	req *retryablehttp.Request
}

var _ Component = &URL{}

// NewURL creates a new URL component
func NewURL() *URL {
	return &URL{}
}

// Name returns the name of the component
func (q *URL) Name() string {
	return RequestURLComponent
}

// Parse parses the component and returns the
// parsed component
func (q *URL) Parse(req *retryablehttp.Request) (bool, error) {
	q.req = req
	q.value = NewValue(req.URL.Path)

	parsed, err := dataformat.Get("raw").Decode(q.value.String())
	if err != nil {
		return false, err
	}
	q.value.SetParsed(parsed, "raw")
	return true, nil
}

// Iterate iterates through the component
func (q *URL) Iterate(callback func(key string, value interface{})) {
	for key, value := range q.value.Parsed() {
		callback(key, value)
	}
}

// SetValue sets a value in the component
// for a key
func (q *URL) SetValue(key string, value string) error {
	if !q.value.SetParsedValue(key, value) {
		return ErrSetValue
	}
	return nil
}

// Rebuild returns a new request with the
// component rebuilt
func (q *URL) Rebuild() (*retryablehttp.Request, error) {
	encoded, err := q.value.Encode()
	if err != nil {
		return nil, errors.Wrap(err, "could not encode query")
	}
	cloned := q.req.Clone(context.Background())
	cloned.URL.Path = encoded
	cloned.Path = encoded
	return cloned, nil
}
