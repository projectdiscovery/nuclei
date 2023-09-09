package component

import (
	"context"

	"github.com/projectdiscovery/retryablehttp-go"
)

// Header is a component for a request header
type Header struct {
	value *Value

	req *retryablehttp.Request
}

var _ Component = &Header{}

// NewHeader creates a new header component
func NewHeader() *Header {
	return &Header{}
}

// Name returns the name of the component
func (q *Header) Name() string {
	return RequestHeaderComponent
}

// Parse parses the component and returns the
// parsed component
func (q *Header) Parse(req *retryablehttp.Request) error {
	q.req = req
	q.value = NewValue("")

	parsedHeaders := make(map[string]interface{})
	for key, value := range req.Header {
		if len(value) == 1 {
			parsedHeaders[key] = value[0]
			continue
		}
		parsedHeaders[key] = value
	}
	q.value.SetParsed(parsedHeaders, "")
	return nil
}

// Iterate iterates through the component
func (q *Header) Iterate(callback func(key string, value interface{})) {
	for key, value := range q.value.Parsed() {
		callback(key, value)
	}
}

// SetValue sets a value in the component
// for a key
func (q *Header) SetValue(key string, value string) error {
	if !q.value.SetParsedValue(key, value) {
		return ErrSetValue
	}
	return nil
}

// Rebuild returns a new request with the
// component rebuilt
func (q *Header) Rebuild() (*retryablehttp.Request, error) {
	cloned := q.req.Clone(context.Background())
	for key, value := range q.value.parsed {
		switch v := value.(type) {
		case []interface{}:
			for _, vv := range v {
				cloned.Header.Add(key, vv.(string))
			}
		case string:
			cloned.Header.Add(key, v)
		}
	}
	return cloned, nil
}
