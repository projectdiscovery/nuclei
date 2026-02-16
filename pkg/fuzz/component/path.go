package component

import (
	"context"
	"strconv"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/dataformat"
	"github.com/projectdiscovery/retryablehttp-go"
	urlutil "github.com/projectdiscovery/utils/url"
)

// Path is a component for a request Path
type Path struct {
	value *Value

	req *retryablehttp.Request

	// keys stores the order of path segments to ensure deterministic iteration.
	// This fixes issue #6398 where numeric segments were skipped due to
	// random map iteration in Go.
	keys []string
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

// Parse parses the component and returns the parsed component
func (q *Path) Parse(req *retryablehttp.Request) (bool, error) {
	q.req = req
	q.value = NewValue("")
	q.keys = []string{} // Reset keys

	splitted := strings.Split(req.Path, "/")
	values := make(map[string]interface{})

	for i, segment := range splitted {
		if segment == "" && i == 0 {
			// Skip the first empty segment from leading "/"
			continue
		}
		if segment == "" {
			// Skip any other empty segments
			continue
		}

		// Create a 1-based index key
		key := strconv.Itoa(len(values) + 1)
		values[key] = segment

		// Store the key in our slice to preserve insertion order
		q.keys = append(q.keys, key)
	}

	q.value.SetParsed(dataformat.KVMap(values), "")
	return true, nil
}

// Iterate iterates through the component segments in a deterministic order
func (q *Path) Iterate(callback func(key string, value interface{}) error) (err error) {
	// Instead of iterating over the random map, we iterate over our ordered keys.
	// This ensures numeric path parts like "/55/" are always processed correctly.
	for _, key := range q.keys {
		// Get the value from the parsed map using the deterministic key
		val := q.value.parsed.Map.GetOrDefault(key, nil)
		if val == nil {
			continue
		}

		if errx := callback(key, val); errx != nil {
			return errx
		}
	}
	return nil
}

// SetValue sets a value in the component for a key
func (q *Path) SetValue(key string, value string) error {
	escaped := urlutil.PathEncode(value)
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

	// Remove the key from our ordered slice as well
	for i, v := range q.keys {
		if v == key {
			q.keys = append(q.keys[:i], q.keys[i+1:]...)
			break
		}
	}
	return nil
}

// Rebuild returns a new request with the component rebuilt
func (q *Path) Rebuild() (*retryablehttp.Request, error) {
	// Get the original path segments
	originalSplitted := strings.Split(q.req.Path, "/")

	// Create a new slice to hold the rebuilt segments
	rebuiltSegments := make([]string, 0, len(originalSplitted))

	// Add the first empty segment (from leading "/")
	if len(originalSplitted) > 0 && originalSplitted[0] == "" {
		rebuiltSegments = append(rebuiltSegments, "")
	}

	// Process each segment using 1-based indexing
	segmentIndex := 1
	for i := 1; i < len(originalSplitted); i++ {
		originalSegment := originalSplitted[i]
		if originalSegment == "" {
			continue
		}

		key := strconv.Itoa(segmentIndex)
		// Retrieve the value (it might have been changed by the fuzzer)
		if newValue, exists := q.value.parsed.Map.GetOrDefault(key, "").(string); exists && newValue != "" {
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

// Clone clones current state to a new component
func (q *Path) Clone() Component {
	// Ensure we deep copy the keys slice to maintain determinism in the clone
	newKeys := make([]string, len(q.keys))
	copy(newKeys, q.keys)

	return &Path{
		value: q.value.Clone(),
		req:   q.req.Clone(context.Background()),
		keys:  newKeys,
	}
}
