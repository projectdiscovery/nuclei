package component

import (
	"context"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/dataformat"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Path is a component for a request Path
type Path struct {
	value *Value

	req *retryablehttp.Request
}

var _ Component = &Path{}

// NewPath creates a new URL component
func NewPath() *Path {
	return &Path{}
}

// Name returns the name of the component
func (q *Path) Name() string {
	return RequestPathComponent
}

// Parse parses the component and returns the
// parsed component
func (q *Path) Parse(req *retryablehttp.Request) (bool, error) {
	q.req = req
	q.value = NewValue(req.URL.Path)

	parsed, err := dataformat.Get(dataformat.RawDataFormat).Decode(q.value.String())
	if err != nil {
		return false, err
	}
	q.value.SetParsed(parsed, dataformat.RawDataFormat)
	return true, nil
}

// Iterate iterates through the component
func (q *Path) Iterate(callback func(key string, value interface{})) {
	for key, value := range q.value.Parsed() {
		callback(key, value)
	}
}

// SetValue sets a value in the component
// for a key
func (q *Path) SetValue(key string, value string) error {
	if !q.value.SetParsedValue(key, value) {
		return ErrSetValue
	}
	return nil
}

// Rebuild returns a new request with the
// component rebuilt
func (q *Path) Rebuild() (*retryablehttp.Request, error) {
	encoded, err := q.value.Encode()
	if err != nil {
		return nil, errors.Wrap(err, "could not encode query")
	}
	cloned := q.req.Clone(context.Background())
	cloned.URL.Path = encoded
	cloned.Path = encoded
	return cloned, nil
}
