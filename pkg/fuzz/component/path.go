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
		// Use 1-based indexing and store individual segments
		key := strconv.Itoa(len(values) + 1)
		values[key] = segment
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

// Rebuild returns a new request with the
// component rebuilt
func (q *Path) Rebuild() (*retryablehttp.Request, error) {
	// Get the original path segments
	originalSplitted := strings.Split(q.req.Path, "/")
	
	// Create a new slice to hold the rebuilt segments
	rebuiltSegments := make([]string, 0, len(originalSplitted))
	
	// Add the first empty segment (from leading "/")
	if len(originalSplitted) > 0 && originalSplitted[0] == "" {
		rebuiltSegments = append(rebuiltSegments, "")
	}
	
	// Process each segment
	segmentIndex := 1 // 1-based indexing for our stored values
	for i := 1; i < len(originalSplitted); i++ {
		originalSegment := originalSplitted[i]
		if originalSegment == "" {
			// Skip empty segments
			continue
		}
		
		// Check if we have a replacement for this segment
		key := strconv.Itoa(segmentIndex)
		if newValue, exists := q.value.parsed.Map.GetOrDefault(key, "").(string); exists && newValue != "" {
			rebuiltSegments = append(rebuiltSegments, newValue)
		} else {
			rebuiltSegments = append(rebuiltSegments, originalSegment)
		}
		segmentIndex++
	}
	
	// Join the segments back into a path
	rebuiltPath := strings.Join(rebuiltSegments, "/")
	
	if unescaped, err := urlutil.PathDecode(rebuiltPath); err == nil {
		// this is handle the case where anyportion of path has url encoded data
		// by default the http/request official library will escape/encode special characters in path
		// to avoid double encoding we unescape/decode already encoded value
		//
		// if there is a invalid url encoded value like %99 then it will still be encoded as %2599 and not %99
		// the only way to make sure it stays as %99 is to implement raw request and unsafe for fuzzing as well
		rebuiltPath = unescaped
	}

	// Clone the request and update the path
	cloned := q.req.Clone(context.Background())
	if err := cloned.UpdateRelPath(rebuiltPath, true); err != nil {
		cloned.RawPath = rebuiltPath
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
