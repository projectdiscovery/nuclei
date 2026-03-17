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
	value        *Value
	req          *retryablehttp.Request
	originalPath string // Snapshot of original path for deterministic rebuilds
}

var _ Component = &Path{}

// NewPath creates a new Path component
func NewPath() *Path {
	return &Path{}
}

// Name returns the name of the component
func (q *Path) Name() string {
	return RequestPathComponent
}

// Parse parses the component and extracts path segments as keys
func (q *Path) Parse(req *retryablehttp.Request) (bool, error) {
	q.req = req
	q.originalPath = req.Path
	q.value = NewValue("")

	splitted := strings.Split(req.Path, "/")
	values := make(map[string]interface{})

	count := 1
	for i, segment := range splitted {
		// Skip leading empty segment from "/"
		if segment == "" && i == 0 {
			continue
		}
		// Skip other empty segments for parsing keys, but they'll be preserved in Rebuild
		if segment == "" {
			continue
		}
		key := strconv.Itoa(count)
		values[key] = segment
		count++
	}
	q.value.SetParsed(dataformat.KVMap(values), "")
	return true, nil
}

// Iterate iterates over the component
func (q *Path) Iterate(callback func(key string, value interface{}) error) (err error) {
	return q.value.Iterate(callback)
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
	return nil
}

// Rebuild returns a new request with the component rebuilt, preserving original structure
func (q *Path) Rebuild() (*retryablehttp.Request, error) {
	originalSplitted := strings.Split(q.originalPath, "/")
	rebuiltSegments := make([]string, 0, len(originalSplitted))

	// Handle leading slash preservation
	if len(originalSplitted) > 0 && originalSplitted[0] == "" {
		rebuiltSegments = append(rebuiltSegments, "")
	}

	segmentIndex := 1
	start := 0
	if len(originalSplitted) > 0 && originalSplitted[0] == "" {
		start = 1
	}

	for i := start; i < len(originalSplitted); i++ {
		originalSegment := originalSplitted[i]
		if originalSegment == "" {
			// Preserve empty segments (e.g., // or trailing /) to maintain request semantics
			rebuiltSegments = append(rebuiltSegments, "")
			continue
		}

		key := strconv.Itoa(segmentIndex)
		// Check for replacement or deletion
		if val, exists := q.value.parsed.Map.Get(key); exists {
			if val == nil {
				// Segment was deleted, do not append anything
			} else if s, ok := val.(string); ok {
				rebuiltSegments = append(rebuiltSegments, s)
			} else {
				rebuiltSegments = append(rebuiltSegments, originalSegment)
			}
		} else {
			rebuiltSegments = append(rebuiltSegments, originalSegment)
		}
		segmentIndex++
	}

	rebuiltPath := strings.Join(rebuiltSegments, "/")

	// Handle URL decoding to prevent double encoding by retryablehttp
	if unescaped, err := urlutil.PathDecode(rebuiltPath); err == nil {
		rebuiltPath = unescaped
	}

	cloned := q.req.Clone(context.Background())
	if err := cloned.UpdateRelPath(rebuiltPath, true); err != nil {
		cloned.RawPath = rebuiltPath
	}
	return cloned, nil
}

// Clone clones the current state to a new component
func (q *Path) Clone() Component {
	return &Path{
		value:        q.value.Clone(),
		req:          q.req.Clone(context.Background()),
		originalPath: q.originalPath,
	}
}