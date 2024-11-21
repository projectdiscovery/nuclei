package component

import (
	"context"
	"strconv"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/dataformat"
	"github.com/projectdiscovery/retryablehttp-go"
	mapsutil "github.com/projectdiscovery/utils/maps"
	urlutil "github.com/projectdiscovery/utils/url"
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
	q.value = NewValue("")

	splitted := strings.Split(req.URL.Path, "/")
	values := make(map[string]interface{})
	for i := range splitted {
		pathTillNow := strings.Join(splitted[:i+1], "/")
		if pathTillNow == "" {
			continue
		}
		values[strconv.Itoa(i)] = pathTillNow
	}
	q.value.SetParsed(dataformat.KVMap(values), "")
	return true, nil
}

// Iterate iterates through the component
func (q *Path) Iterate(callback func(key string, value interface{}) error) (err error) {
	q.value.parsed.Iterate(func(key string, value any) bool {
		if errx := callback(key, value); errx != nil {
			err = errx
			return false
		}
		return true
	})
	return
}

// SetValue sets a value in the component
// for a key
func (q *Path) SetValue(key string, value string) error {
	escaped := urlutil.ParamEncode(value)
	if !q.value.SetParsedValue(key, escaped) {
		return ErrSetValue
	}
	return nil
}

// Delete deletes a key from the component
func (q *Path) Delete(key string) error {
	if !q.value.Delete(key) {
		return ErrKeyNotFound
	}
	return nil
}

// Rebuild returns a new request with the
// component rebuilt
func (q *Path) Rebuild() (*retryablehttp.Request, error) {
	originalValues := mapsutil.Map[string, any]{}
	splitted := strings.Split(q.req.URL.Path, "/")
	for i := range splitted {
		pathTillNow := strings.Join(splitted[:i+1], "/")
		if pathTillNow == "" {
			continue
		}
		originalValues[strconv.Itoa(i)] = pathTillNow
	}

	originalPath := q.req.URL.Path
	lengthSplitted := len(q.value.parsed.Map)
	for i := lengthSplitted; i > 0; i-- {
		key := strconv.Itoa(i)

		original, ok := originalValues.GetOrDefault(key, "").(string)
		if !ok {
			continue
		}

		new, ok := q.value.parsed.Map.GetOrDefault(key, "").(string)
		if !ok {
			continue
		}

		if new == original {
			// no need to replace
			continue
		}

		originalPath = strings.Replace(originalPath, original, new, 1)
	}

	rebuiltPath := originalPath

	// Clone the request and update the path
	cloned := q.req.Clone(context.Background())
	if err := cloned.UpdateRelPath(rebuiltPath, true); err != nil {
		cloned.URL.RawPath = rebuiltPath
	}
	return cloned, nil
}

// Clones current state to a new component
func (q *Path) Clone() Component {
	return &Path{
		value: q.value.Clone(),
		req:   q.req.Clone(context.Background()),
	}
}
