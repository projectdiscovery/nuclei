package dns

import "github.com/projectdiscovery/nuclei/v2/pkg/quarks/matchers"

// Compile returns the compiled version of a request
func (r *Request) Compile() (*CompiledRequest, error) {
	compiled := &CompiledRequest{AtomicRequests: make([]*AtomicRequest, 1)}
	request := &AtomicRequest{
		FQDN:      r.Name,
		Retries:   r.Retries,
		Recursive: r.Recursion,
		ReqType:   toQType(r.Type),
		Class:     toQClass(r.Class),
	}

	condition, ok := matchers.ConditionTypes[r.MatchersCondition]
	if !ok {
		request.MatchersCondition = matchers.ORCondition
	} else {
		request.MatchersCondition = condition
	}

	for _, matcher := range r.Matchers {
		compiled, err := matcher.Compile()
		if err != nil {
			return nil, err
		}
		request.Matchers = append(request.Matchers, compiled)
	}

	for _, extractor := range r.Extractors {
		compiled, err := extractor.Compile()
		if err != nil {
			return nil, err
		}
		request.Extractors = append(request.Extractors, compiled)
	}
	compiled.AtomicRequests[0] = request
	return compiled, nil
}
