package http

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
)

// requestGenerator generates requests sequentially based on various
// configurations for a http request template.
//
// If payload values are present, an iterator is created for the payload
// values. Paths and Raw requests are supported as base input, so
// it will automatically select between them based on the template.
type requestGenerator struct {
	currentIndex    int
	request         *Request
	options         *protocols.ExecuterOptions
	payloadIterator *generators.Iterator
	interactshURLs  []string
}

// newGenerator creates a new request generator instance
func (request *Request) newGenerator() *requestGenerator {
	generator := &requestGenerator{request: request, options: request.options}

	if len(request.Payloads) > 0 {
		generator.payloadIterator = request.generator.NewIterator()
	}
	return generator
}

// nextValue returns the next path or the next raw request depending on user input
// It returns false if all the inputs have been exhausted by the generator instance.
func (r *requestGenerator) nextValue() (value string, payloads map[string]interface{}, result bool) {
	// For both raw/path requests, start with the request at current index.
	// If we are not at the start, then check if the iterator for payloads
	// has finished if there are any.
	//
	// If the iterator has finished for the current request
	// then reset it and move on to the next value, otherwise use the last request.

	if len(r.request.Path) > 0 && r.currentIndex < len(r.request.Path) {
		if r.payloadIterator != nil {
			payload, ok := r.payloadIterator.Value()
			if !ok {
				r.currentIndex++
				r.payloadIterator.Reset()

				// No more payloads request for us now.
				if len(r.request.Path) == r.currentIndex {
					return "", nil, false
				}
				if item := r.request.Path[r.currentIndex]; item != "" {
					newPayload, ok := r.payloadIterator.Value()
					return item, newPayload, ok
				}
				return "", nil, false
			}
			return r.request.Path[r.currentIndex], payload, true
		}
		if value := r.request.Path[r.currentIndex]; value != "" {
			r.currentIndex++
			return value, nil, true
		}
	}

	if len(r.request.Raw) > 0 && r.currentIndex < len(r.request.Raw) {
		if r.payloadIterator != nil {
			payload, ok := r.payloadIterator.Value()
			if !ok {
				r.currentIndex++
				r.payloadIterator.Reset()

				// No more payloads request for us now.
				if len(r.request.Raw) == r.currentIndex {
					return "", nil, false
				}
				if item := r.request.Raw[r.currentIndex]; item != "" {
					newPayload, ok := r.payloadIterator.Value()
					return item, newPayload, ok
				}
				return "", nil, false
			}
			return r.request.Raw[r.currentIndex], payload, true
		}
		if item := r.request.Raw[r.currentIndex]; item != "" {
			r.currentIndex++
			return item, nil, true
		}
	}
	return "", nil, false
}
