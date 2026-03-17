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
	originalPath string // Snapshot of original path
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

// Parse parses the component
func (q *Path) Parse(req *retryablehttp.Request) (bool, error) {
	q.req = req
	q.originalPath = req.Path
	q.value = NewValue("")

	splitted := strings.Split(req.Path, "/")
	values := make(map[string]interface{})

	count := 1
	for i, segment := range splitted {
		if segment == "" && i == 0 {
			continue
		}
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

// SetValue sets a value in the component
func (q *Path) SetValue(key string, value string) error {
	escaped := urlutil.PathEncode(value)
	if !q.value.SetParsedValue(key, escaped) {
		return ErrKeyNotFound
	}
	return nil
}

// Delete deletes a key from the component
func (q *Path) Delete(key string) error {
	return nil
}

// Rebuild returns a new request with the component rebuilt
func (q *Path) Rebuild() (*retryablehttp.Request, error) {
	originalSplitted := strings.Split(q.originalPath, "/")
	rebuiltSegments := make([]string, 0, len(originalSplitted))

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
			continue
		}

		key := strconv.Itoa(segmentIndex)
		if val, exists := q.value.parsed.Map.Get(key); exists && val != "" {
			rebuiltSegments = append(rebuiltSegments, val.(string))
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

// Clone clones the current state to a new component
func (q *Path) Clone() Component {
	return &Path{
		value:        q.value.Clone(),
		req:          q.req.Clone(context.Background()),
		originalPath: q.originalPath,
	}
}