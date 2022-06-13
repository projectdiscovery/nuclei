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
}

// LeaveDefaultPorts skips normalization of default standard ports
var LeaveDefaultPorts = false

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
	hasInitializedPayloads := r.currentPayloads != nil

	if r.currentIndex == 0 && hasPayloadIterator && !hasInitializedPayloads {
		r.currentPayloads, r.okCurrentPayload = r.payloadIterator.Value()
	}
	if r.currentIndex < len(sequence) {
		currentRequest := sequence[r.currentIndex]
		r.currentIndex++
		return currentRequest, r.currentPayloads, true
	}
	if r.currentIndex == len(sequence) {
		if r.okCurrentPayload {
			r.currentIndex = 0
			currentRequest := sequence[r.currentIndex]
			if hasPayloadIterator {
				r.currentPayloads, r.okCurrentPayload = r.payloadIterator.Value()
				if r.okCurrentPayload {
					r.currentIndex++
					return currentRequest, r.currentPayloads, true
				}
			}
		}
	}

	return "", nil, false
}
