// Package replay stores the event every request hands its matchers and
// extractors, for any protocol, and runs templates over a stored corpus again
// without sending anything. Comparing the findings of two template sets or
// two builds on the same corpus shows what a change moved.
package replay

import (
	"os"
	"strconv"
	"sync"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

// record is one line of a corpus.
type record[E any] struct {
	TemplateID string `json:"template-id,omitempty"`
	// Request is the position of the request in its template.
	Request int `json:"request"`
	// ClusterKey identifies the request of a single-request template; every
	// template sending the same request replays the event, as the scan
	// clusters them onto one.
	ClusterKey string `json:"cluster-key,omitempty"`
	Event      E      `json:"event"`
}

type requestRef struct {
	templateID string
	index      int
	single     bool
}

// Recorder appends the events of a scan to a corpus file.
type Recorder struct {
	mu       sync.Mutex
	file     *os.File
	requests map[protocols.Request]requestRef
	err      error
}

// clusterKeyed is a request the scan can cluster. The key leaves out what
// makes a request unclusterable, such as a raw request or a body, so only a
// clusterable request may share events by it.
type clusterKeyed interface {
	TmplClusterKey() uint64
	IsClusterable() bool
}

func clusterKey(request protocols.Request) (string, bool) {
	keyed, ok := request.(clusterKeyed)
	if !ok || !keyed.IsClusterable() {
		return "", false
	}
	return strconv.FormatUint(keyed.TmplClusterKey(), 10), true
}

// NewRecorder creates the corpus at path for a scan of templatesList. The
// corpus holds raw traffic, credentials included, so only its owner can read
// it.
func NewRecorder(path string, templatesList []*templates.Template) (*Recorder, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	recorder := &Recorder{file: file, requests: make(map[protocols.Request]requestRef)}
	for _, source := range sources(templatesList) {
		single := len(source.requests) == 1 && source.clustered
		for i, request := range source.requests {
			recorder.requests[request] = requestRef{templateID: source.id, index: i, single: single}
		}
	}
	return recorder, nil
}

// Record stores event, which request produced. It runs before the operators,
// which add their own values to the event.
func (r *Recorder) Record(request protocols.Request, event output.InternalEvent) {
	ref, known := r.requests[request]
	if !known {
		// a cluster runs one request for all its members and was compiled
		// apart from them; its members replay it by the cluster key
		key, ok := clusterKey(request)
		if !ok {
			return
		}
		templateID, _ := event["template-id"].(string)
		r.write(record[map[string]any]{TemplateID: templateID, ClusterKey: key, Event: encodeEvent(event)})
		return
	}
	line := record[map[string]any]{TemplateID: ref.templateID, Request: ref.index, Event: encodeEvent(event)}
	if key, ok := clusterKey(request); ok && ref.single {
		line.ClusterKey = key
	}
	r.write(line)
}

func (r *Recorder) write(line record[map[string]any]) {
	data, err := json.Marshal(line)
	if err != nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// written straight to the file: ctrl+c exits without running defers
	if _, err := r.file.Write(append(data, '\n')); err != nil && r.err == nil {
		r.err = err
	}
}

// Close closes the corpus and reports the first write error.
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.file.Close(); err != nil && r.err == nil {
		r.err = err
	}
	return r.err
}
