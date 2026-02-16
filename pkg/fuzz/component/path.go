package component

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/dataformat"
	"github.com/projectdiscovery/retryablehttp-go"
	urlutil "github.com/projectdiscovery/utils/url"
)

// Path is a component for a request URL Path that supports deterministic iteration.
type Path struct {
	value *Value
	req   *retryablehttp.Request
	keys  []string
}

var _ Component = &Path{}

// NewPath creates a new Path component instance.
func NewPath() *Path {
	return &Path{}
}

// Name returns the identifier for the Path component.
func (q *Path) Name() string {
	return RequestPathComponent
}

// Parse dissects the request path into individual segments and stores them internally.
func (q *Path) Parse(req *retryablehttp.Request) (bool, error) {
	q.req = req
	q.value = NewValue("")
	q.keys = []string{}

	splitted := strings.Split(req.Path, "/")
	values := make(map[string]interface{})

	for i, segment := range splitted {
		if segment == "" && i == 0 {
			continue
		}
		if segment == "" {
			continue
		}

		key := strconv.Itoa(len(values) + 1)
		values[key] = segment
		q.keys = append(q.keys, key)
	}

	q.value.SetParsed(dataformat.KVMap(values), "")
	return true, nil
}

// Iterate traverses the path segments in the exact order they appear in the URL.
func (q *Path) Iterate(callback func(key string, value interface{}) error) (err error) {
	for _, key := range q.keys {
		if !q.value.parsed.Map.Has(key) {
			return fmt.Errorf("path component: key %q present in keys slice but missing from parsed map", key)
		}

		val := q.value.parsed.Map.GetOrDefault(key, nil)
		if errx := callback(key, val); errx != nil {
			return errx
		}
	}
	return nil
}

// SetValue replaces a specific path segment identified by its key with a new value.
func (q *Path) SetValue(key string, value string) error {
	escaped := urlutil.PathEncode(value)
	if !q.value.SetParsedValue(key, escaped) {
		return ErrSetValue
	}
	return nil
}

// Delete removes a path segment from the component and updates the order tracking.
func (q *Path) Delete(key string) error {
	if !q.value.Delete(key) {
		return ErrKeyNotFound
	}

	for i, v := range q.keys {
		if v == key {
			q.keys = append(q.keys[:i], q.keys[i+1:]...)
			break
		}
	}
	return nil
}

// Rebuild constructs a new HTTP request with the modified path segments.
func (q *Path) Rebuild() (*retryablehttp.Request, error) {
	originalSplitted := strings.Split(q.req.Path, "/")
	rebuiltSegments := make([]string, 0, len(originalSplitted))

	if len(originalSplitted) > 0 && originalSplitted[0] == "" {
		rebuiltSegments = append(rebuiltSegments, "")
	}

	segmentIndex := 1
	for i := 1; i < len(originalSplitted); i++ {
		originalSegment := originalSplitted[i]
		if originalSegment == "" {
			continue
		}

		key := strconv.Itoa(segmentIndex)
		if !q.value.parsed.Map.Has(key) {
			segmentIndex++
			continue
		}

		if newValue, ok := q.value.parsed.Map.GetOrDefault(key, "").(string); ok && newValue != "" {
			rebuiltSegments = append(rebuiltSegments, newValue)
		} else {
			rebuiltSegments = append(rebuiltSegments, originalSegment)
		}
		segmentIndex++
	}

	rebuiltPath := strings.Join(rebuiltSegments, "/")
	if unescaped, err := urlutil.PathDecode(rebuiltPath); err == nil {
		rebuiltPath = unescaped
	}

	cloned := q.req.Clone(context.Background())
	if err := cloned.UpdateRelPath(rebuiltPath, true); err != nil {
		cloned.RawPath = rebuiltPath
	}
	return cloned, nil
}

// Clone creates a deep copy of the Path component, including the deterministic keys.
func (q *Path) Clone() Component {
	newKeys := make([]string, len(q.keys))
	copy(newKeys, q.keys)

	return &Path{
		value: q.value.Clone(),
		req:   q.req.Clone(context.Background()),
		keys:  newKeys,
	}
}
