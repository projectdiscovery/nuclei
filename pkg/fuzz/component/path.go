package component

import (
	"context"
	"strconv"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/dataformat"
	"github.com/projectdiscovery/retryablehttp-go"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

type Path struct {
	value        *Value
	req          *retryablehttp.Request
	originalPath string
}

var _ Component = &Path{}

func NewPath() *Path {
	return &Path{}
}

func (q *Path) Name() string {
	return "path"
}

func (q *Path) Parse(req *retryablehttp.Request) (bool, error) {
	q.req = req
	q.originalPath = req.Path
	q.value = NewValue("")

	splitted := strings.Split(req.Path, "/")
	values := mapsutil.NewOrderedMap[string, any]()

	for i, segment := range splitted {
		if segment == "" && i == 0 {
			continue
		}
		key := strconv.Itoa(values.Len() + 1)
		values.Set(key, segment)
	}

	q.value.SetParsed(dataformat.KVOrderedMap(&values), "")
	return true, nil
}

func (q *Path) Rebuild() (*retryablehttp.Request, error) {
	originalSplitted := strings.Split(q.originalPath, "/")

	rebuiltSegments := make([]string, 0, len(originalSplitted))

	counter := 1
	for i, originalSegment := range originalSplitted {
		if i == 0 && originalSegment == "" {
			rebuiltSegments = append(rebuiltSegments, "")
			continue
		}

		key := strconv.Itoa(counter)
		if newValue := q.value.parsed.Get(key); newValue != nil {
			rebuiltSegments = append(rebuiltSegments, newValue.(string))
		} else {
			rebuiltSegments = append(rebuiltSegments, originalSegment)
		}
		counter++
	}

	newPath := strings.Join(rebuiltSegments, "/")

	newReq := q.req.Clone(context.Background())

	// 🔥 critical fix: prevent URL pointer mutation
	if newReq.URL != nil {
		u := *newReq.URL
		newReq.URL = &u
		newReq.URL.Path = newPath
	}

	newReq.Path = newPath

	return newReq, nil
}

func (q *Path) Clone() Component {
	return &Path{
		value:        q.value.Clone(),
		req:          q.req.Clone(context.Background()),
		originalPath: q.originalPath,
	}
}
