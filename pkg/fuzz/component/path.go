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

	req          *retryablehttp.Request
	originalPath string // snapshot of path at parse time to avoid mutation issues
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
	q.originalPath = req.Path
	q.value = NewValue("")

	splitted := strings.Split(req.Path, "/")
	// Use an ordered map to preserve segment order and avoid flat.Flatten
	// converting numeric-keyed maps into slices, which would break type assertions
	// during Rebuild.
	segments := mapsutil.NewOrderedMap[string, any]()
	idx := 1
	for i, segment := range splitted {
		if segment == "" && i == 0 {
			// Skip the first empty segment from leading "/"
			continue
		}
		if segment == "" {
			// Skip any other empty segments
			continue
		}
		key := strconv.Itoa(idx)
		segments.Set(key, segment)
		idx++
	}
	q.value.SetParsed(dataformat.KVOrderedMap(&segments), "")
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
	// Use the original path snapshot to avoid reading from a mutated request URL
	originalSplitted := strings.Split(q.originalPath, "/")

	// Create a new slice to hold the rebuilt segments
	rebuiltSegments := make([]string, 0, len(originalSplitted))

	// Add the first empty segment (from leading "/")
	if len(originalSplitted) > 0 && originalSplitted[0] == "" {
		rebuiltSegments = append(rebuiltSegments, "")
	}

	// Process each segment, looking up replacements from the ordered map
	segmentIndex := 1 // 1-based indexing matching Parse
	for i := 1; i < len(originalSplitted); i++ {
		originalSegment := originalSplitted[i]
		if originalSegment == "" {
			// Skip empty segments
			continue
		}

		// Retrieve from OrderedMap to avoid type-assertion failures caused by
		// flat.Flatten converting numeric-keyed maps into slices.
		key := strconv.Itoa(segmentIndex)
		if newValue, ok := q.value.parsed.OrderedMap.Get(key); ok {
			if strVal, isStr := newValue.(string); isStr && strVal != "" {
				rebuiltSegments = append(rebuiltSegments, strVal)
			} else {
				rebuiltSegments = append(rebuiltSegments, originalSegment)
			}
		} else {
			rebuiltSegments = append(rebuiltSegments, originalSegment)
		}
		segmentIndex++
	}

	// Join the segments back into a path
	rebuiltPath := strings.Join(rebuiltSegments, "/")

	if unescaped, err := urlutil.PathDecode(rebuiltPath); err == nil {
		// Handle the case where any portion of the path has URL encoded data.
		// By default the http/request library will escape/encode special characters
		// in path; to avoid double encoding we unescape already-encoded values.
		//
		// If there is an invalid URL encoded value like %99 it will still be
		// encoded as %2599. To make it stay as %99, raw/unsafe request support
		// would be required.
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
		value:        q.value.Clone(),
		req:          q.req.Clone(context.Background()),
		originalPath: q.originalPath,
	}
}
