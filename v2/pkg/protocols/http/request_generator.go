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
	currentIndex     int
	currentPayloads  map[string]interface{}
	okCurrentPayload bool
	request          *Request
	options          *protocols.ExecuterOptions
	payloadIterator  *generators.Iterator
	interactshURLs   []string
	onceFlow         map[string]struct{}
}

// LeaveDefaultPorts skips normalization of default standard ports
var LeaveDefaultPorts = false

// newGenerator creates a new request generator instance
func (request *Request) newGenerator() *requestGenerator {
	generator := &requestGenerator{
		request:  request,
		options:  request.options,
		onceFlow: make(map[string]struct{}),
	}

	if len(request.Payloads) > 0 {
		generator.payloadIterator = request.generator.NewIterator()
	}
	return generator
}

// nextValue returns the next path or the next raw request depending on user input
// It returns false if all the inputs have been exhausted by the generator instance.
func (r *requestGenerator) nextValue() (value string, payloads map[string]interface{}, result bool) {
	// Iterate each payload sequentially for each request path/raw
	//
	// If the sequence has finished for the current payload values
	// then restart the sequence from the beginning and move on to the next payloads values
	// otherwise use the last request.
	var sequence []string
	switch {
	case len(r.request.Path) > 0:
		sequence = r.request.Path
	case len(r.request.Raw) > 0:
		sequence = r.request.Raw
	default:
		return "", nil, false
	}

	hasPayloadIterator := r.payloadIterator != nil

	if hasPayloadIterator && r.currentPayloads == nil {
		r.currentPayloads, r.okCurrentPayload = r.payloadIterator.Value()
	}

	var request string
	var shouldContinue bool
	if nextRequest, nextIndex, found := r.findNextIteration(sequence, r.currentIndex); found {
		r.currentIndex = nextIndex + 1
		request = nextRequest
		shouldContinue = true
	} else if nextRequest, nextIndex, found := r.findNextIteration(sequence, 0); found && hasPayloadIterator {
		r.currentIndex = nextIndex + 1
		request = nextRequest
		shouldContinue = true
	}

	if shouldContinue {
		if r.hasMarker(request, Once) {
			r.applyMark(request, Once)
		}
		if hasPayloadIterator {
			return request, r.currentPayloads, r.okCurrentPayload
		}
		return request, r.currentPayloads, true
	} else {
		return "", nil, false
	}
}

func (r *requestGenerator) findNextIteration(sequence []string, index int) (string, int, bool) {
	for i, request := range sequence[index:] {
		if !r.wasMarked(request, Once) {
			return request, index + i, true
		}
	}

	if r.payloadIterator != nil {
		r.currentPayloads, r.okCurrentPayload = r.payloadIterator.Value()
	}

	return "", 0, false
}

func (r *requestGenerator) applyMark(request string, mark flowMark) {
	switch mark {
	case Once:
		r.onceFlow[request] = struct{}{}
	}

}

func (r *requestGenerator) wasMarked(request string, mark flowMark) bool {
	switch mark {
	case Once:
		_, ok := r.onceFlow[request]
		return ok
	}
	return false
}

func (r *requestGenerator) hasMarker(request string, mark flowMark) bool {
	fo, hasOverrides := parseFlowAnnotations(request)
	return hasOverrides && fo == mark
}
