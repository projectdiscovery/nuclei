package http

import (
	"reflect"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/replacer"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
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
	currentPosition int
	totalEvaluated  int
	prevPayload     map[string]interface{}
}

// newGenerator creates a new request generator instance
func (r *Request) newGenerator() *requestGenerator {
	generator := &requestGenerator{request: r, options: r.options}
	if len(r.Payloads) > 0 {
		if r.attackType == generators.Sniper {
			for k := range r.Payloads {
				r.generator.TotalPositionCount += generator.payloadPositionCount(k)
			}
		}
		generator.payloadIterator = r.generator.NewIterator()
	}
	return generator
}

// nextValue returns the next path or the next raw request depending on user input
// It returns false if all the inputs have been exhausted by the generator instance.
func (r *requestGenerator) nextValue() (string, map[string]interface{}, bool) {

	switch {
	case len(r.request.Path) > 0 && r.currentIndex < len(r.request.Path):
		return r.fetchValue(r.request.Path)
	case len(r.request.Raw) > 0 && r.currentIndex < len(r.request.Raw):
		return r.fetchValue(r.request.Raw)
	default:
		return "", nil, false
	}
}

func (r *requestGenerator) fetchValue(data []string) (value string, payloads map[string]interface{}, ok bool) {
	// Start with the request at current index.
	// If we are not at the start, then check if the iterator for payloads
	// has finished if there are any.
	//
	// If the iterator has finished for the current request
	// then reset it and move on to the next value, otherwise use the last request.
	if r.payloadIterator == nil {
		if value = data[r.currentIndex]; value != "" {
			r.currentIndex++
			return value, nil, true
		}
	} else {
		payloads, ok = r.payloadIterator.Value()
		if !ok {
			r.currentIndex++
			r.payloadIterator.Reset()

			// No more payloads request for us now.
			if len(data) == r.currentIndex {
				return "", nil, false
			}
			if value = data[r.currentIndex]; value == "" {
				return "", nil, false
			} else {
				payloads, ok = r.payloadIterator.Value()
			}
		} else {
			value = data[r.currentIndex]
		}
	}
	if r.request.attackType == generators.Sniper {
		r.setCurrentPosition(r.prevPayload, payloads)
	}
	return
}

func (r *requestGenerator) setCurrentPosition(prevPayload, payload map[string]interface{}) {
	r.totalEvaluated = 0
	if reflect.DeepEqual(prevPayload, payload) {
		r.currentPosition++
	} else {
		r.currentPosition = 1
	}
	r.prevPayload = payload
}

// setPayloadPositionValues calculates the position count and sets values to be used while parsing
func (r *requestGenerator) payloadPositionCount(key string) int {
	regex := utils.PlaceholderRegex(key)

	dataPositionCount := 0
	for _, value := range r.request.Path {
		dataPositionCount += len(regex.FindAllStringIndex(value, -1))
	}
	for _, value := range r.request.Raw {
		dataPositionCount += len(regex.FindAllStringIndex(value, -1))
	}

	bodyPositionCount := len(regex.FindAllStringIndex(r.request.Body, -1))
	methodPositionCount := len(regex.FindAllStringIndex(r.request.Method, -1))

	headerPositionCount := 0
	for _, v := range r.request.Headers {
		headerPositionCount += len(regex.FindAllStringIndex(v, -1))
	}
	// total number of payload positions
	return dataPositionCount +
		bodyPositionCount +
		methodPositionCount +
		headerPositionCount
}

// replaceSniperPosition parses the payload positions for sniper attack type
func (r *requestGenerator) replaceSniperPositions(template string, payloads map[string]interface{}) string {
	for key, value := range payloads {
		result, count := replacer.ReplaceNth(template, key, value.(string), r.currentPosition-r.totalEvaluated)
		r.totalEvaluated += count
		return result
	}
	return template
}
