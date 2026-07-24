package component

import (
	"context"
	"net/http"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/dataformat"
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
func (q *Header) Parse(req *retryablehttp.Request) (bool, error) {
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
	q.value.SetParsed(dataformat.KVMap(parsedHeaders), "")
	return true, nil
}

// Iterate iterates through the component
func (q *Header) Iterate(callback func(key string, value interface{}) error) (errx error) {
	q.value.parsed.Iterate(func(key string, value any) bool {
		// Skip ignored headers (keys stored as http.CanonicalHeaderKey).
		if _, ok := defaultIgnoredHeaderKeys[http.CanonicalHeaderKey(key)]; ok {
			return true
		}
		if err := callback(key, value); err != nil {
			errx = err
			return false
		}
		return true
	})
	return
}

// SetValue sets a value in the component
// for a key
func (q *Header) SetValue(key string, value string) error {
	if !q.value.SetParsedValue(key, value) {
		return ErrSetValue
	}
	return nil
}

// Delete deletes a key from the component
func (q *Header) Delete(key string) error {
	if !q.value.Delete(key) {
		return ErrKeyNotFound
	}
	return nil
}

// Rebuild returns a new request with the
// component rebuilt
func (q *Header) Rebuild() (*retryablehttp.Request, error) {
	cloned := q.req.Clone(context.Background())
	q.value.parsed.Iterate(func(key string, value any) bool {
		if strings.TrimSpace(key) == "" {
			return true
		}
		if strings.EqualFold(key, "Host") {
			return true
		}
		if vx, ok := IsTypedSlice(value); ok {
			// convert to []interface{}
			value = vx
		}
		if v, ok := value.([]interface{}); ok {
			for _, vv := range v {
				cloned.Header.Add(key, vv.(string))
			}
			return true
		}
		cloned.Header.Set(key, value.(string))
		return true
	})
	return cloned, nil
}

// Clones current state of this component
func (q *Header) Clone() Component {
	return &Header{
		value: q.value.Clone(),
		req:   q.req.Clone(context.Background()),
	}
}
