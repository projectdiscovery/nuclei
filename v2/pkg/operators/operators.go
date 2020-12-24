package operators

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
)

// Operators contains the operators that can be applied on protocols
type Operators struct {
	// Matchers contains the detection mechanism for the request to identify
	// whether the request was successful
	Matchers []*matchers.Matcher `yaml:"matchers"`
	// Extractors contains the extraction mechanism for the request to identify
	// and extract parts of the response.
	Extractors []*extractors.Extractor `yaml:"extractors"`
	// MatchersCondition is the condition of the matchers
	// whether to use AND or OR. Default is OR.
	MatchersCondition string `yaml:"matchers-condition"`
	// cached variables that may be used along with request.
	matchersCondition matchers.ConditionType
}

// GetMatchersCondition returns the condition for the matchers
func (r *Operators) GetMatchersCondition() matchers.ConditionType {
	return r.matchersCondition
}

// Result is a result structure created from operators running on data.
type Result struct {
	// Matches is a map of matcher names that we matched
	Matches map[string]struct{}
	// Extracts contains all the data extracted from inputs
	Extracts map[string][]string
	// DynamicValues contains any dynamic values to be templated
	DynamicValues map[string]string
}

// Execute executes the operators on data and returns a result structure
func (r *Operators) Execute(data map[string]interface{}) (*Result, bool) {
	matcherCondition := r.GetMatchersCondition()

	result := &Result{
		Matches:       make(map[string]struct{}),
		Extracts:      make(map[string][]string),
		DynamicValues: make(map[string]string),
	}
	for _, matcher := range r.Matchers {
		// Check if the matcher matched
		if !matcher.Match(data) {
			// If the condition is AND we haven't matched, try next request.
			if matcherCondition == matchers.ANDCondition {
				return nil, false
			}
		} else {
			// If the matcher has matched, and its an OR
			// write the first output then move to next matcher.
			if matcherCondition == matchers.ORCondition {
				result.Matches[matcher.Name] = struct{}{}
			}
		}
	}

	// All matchers have successfully completed so now start with the
	// next task which is extraction of input from matchers.
	var extractorResults, outputExtractorResults []string
	for _, extractor := range r.Extractors {
		for match := range extractor.Extract(data) {
			extractorResults = append(extractorResults, match)

			if extractor.Internal {
				if _, ok := result.DynamicValues[extractor.Name]; !ok {
					result.DynamicValues[extractor.Name] = match
				}
			} else {
				outputExtractorResults = append(outputExtractorResults, match)
			}
		}
		result.Extracts[extractor.Name] = extractorResults
	}

	// Write a final string of output if matcher type is
	// AND or if we have extractors for the mechanism too.
	if len(result.Extracts) > 0 || len(result.Matches) > 0 || matcherCondition == matchers.ANDCondition {
		return result, true
	}
	return nil, false
}
