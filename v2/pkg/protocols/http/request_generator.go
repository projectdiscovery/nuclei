package http

import (
	"sort"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/replacer"
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
	sniperData      *sniperData
	payloads        map[string]interface{}
}

type sniperData struct {
	currentPosition     int
	sniperPositionCount int
	dataPositionCount   int
	bodyPositionCount   int
	methodPositionCount int
	headerPositionCount int
	originalData        string
	data                string
	originalHeaders     map[string]string
	headers             map[string]string
	method              string
	body                string
}

// newGenerator creates a new request generator instance
func (r *Request) newGenerator() *requestGenerator {
	generator := &requestGenerator{request: r, options: r.options}
	generator.sniperData = &sniperData{
		currentPosition:     1,
		sniperPositionCount: 0,
		headers:             make(map[string]string),
		originalHeaders:     r.Headers,
		method:              r.Method,
		body:                r.Body,
	}
	if len(r.Payloads) > 0 {
		generator.payloadIterator = r.generator.NewIterator()
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

// setPayloadPositionValues calculates the position count and sets values to be used while parsing
func (r *requestGenerator) setPayloadPositionValues(data string, payloads map[string]interface{}) {
	r.sniperData.originalData = data
	r.payloads = payloads

	r.sniperData.currentPosition = 1

	r.sniperData.dataPositionCount = strings.Count(r.sniperData.originalData, "§") / 2
	r.sniperData.bodyPositionCount = strings.Count(r.request.Body, "§") / 2
	r.sniperData.methodPositionCount = strings.Count(r.request.Method, "§") / 2

	headerPositionCount := 0
	for _, v := range r.sniperData.originalHeaders {
		headerPositionCount += strings.Count(v, "§") / 2
	}
	r.sniperData.headerPositionCount = headerPositionCount

	// total number of payload positions
	r.sniperData.sniperPositionCount = r.sniperData.dataPositionCount +
		r.sniperData.bodyPositionCount +
		r.sniperData.methodPositionCount +
		r.sniperData.headerPositionCount
}


// replaceSniperPosition parses the payload positions for sniper attack type
func (r *requestGenerator) replaceSniperPositions() {
	position := r.sniperData.currentPosition

	for key, value := range r.payloads {
		r.sniperData.data = replacer.ReplaceNth(r.sniperData.originalData, key, value.(string), position)

		position -= r.sniperData.dataPositionCount
		r.sniperData.body = replacer.ReplaceNth(r.request.Body, key, value.(string), position)

		position -= r.sniperData.bodyPositionCount
		r.sniperData.method = replacer.ReplaceNth(r.request.Method, key, value.(string), position)

		position -= r.sniperData.methodPositionCount
		i := 0
		// get ordered header keys to iterate over
		for _, v := range getOrderedKeys(r.sniperData.originalHeaders) {
			r.sniperData.headers[v] = replacer.ReplaceNth(r.sniperData.originalHeaders[v], key, value.(string), position-i)
			i++
		}
		r.sniperData.currentPosition++
		return
	}
}

func getOrderedKeys(headers map[string]string) (keys []string) {
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return
}
