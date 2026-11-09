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
	mu        sync.Mutex
	file      *os.File
	requests  map[protocols.Request]requestRef
	singleIDs map[string]bool
	err       error
}

type clusterKeyed interface {
	TmplClusterKey() uint64
}

type requestLister interface {
	ProtocolRequests() []protocols.Request
}

// NewRecorder creates the corpus at path for a scan of templatesList.
func NewRecorder(path string, templatesList []*templates.Template) (*Recorder, error) {
	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	recorder := &Recorder{file: file, requests: make(map[protocols.Request]requestRef), singleIDs: make(map[string]bool)}
	for _, template := range templatesList {
		requests := templateRequests(template)
		for i, request := range requests {
			recorder.requests[request] = requestRef{templateID: template.ID, index: i, single: len(requests) == 1}
		}
		if len(requests) == 1 {
			recorder.singleIDs[template.ID] = true
		}
	}
	return recorder, nil
}

func templateRequests(template *templates.Template) []protocols.Request {
	if lister, ok := template.Executer.(requestLister); ok {
		return lister.ProtocolRequests()
	}
	return nil
}

// Record stores event, which request produced. It runs before the operators,
// which add their own values to the event.
func (r *Recorder) Record(request protocols.Request, event output.InternalEvent) {
	ref, known := r.requests[request]
	if !known {
		// a cluster runs the first member's request, which the scan compiled
		// apart from the template list
		templateID, _ := event["template-id"].(string)
		if !r.singleIDs[templateID] {
			return
		}
		ref = requestRef{templateID: templateID, single: true}
	}
	line := record[map[string]any]{TemplateID: ref.templateID, Request: ref.index, Event: encodeEvent(event)}
	if keyed, ok := request.(clusterKeyed); ok && ref.single {
		line.ClusterKey = strconv.FormatUint(keyed.TmplClusterKey(), 10)
	}
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
