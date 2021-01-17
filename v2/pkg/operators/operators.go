package operators

import (
	"github.com/pkg/errors"
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

// Compile compiles the operators as well as their corresponding matchers and extractors
func (r *Operators) Compile() error {
	if r.MatchersCondition != "" {
		r.matchersCondition = matchers.ConditionTypes[r.MatchersCondition]
	} else {
		r.matchersCondition = matchers.ORCondition
	}

	for _, matcher := range r.Matchers {
		if err := matcher.CompileMatchers(); err != nil {
			return errors.Wrap(err, "could not compile matcher")
		}
	}
	for _, extractor := range r.Extractors {
		if err := extractor.CompileExtractors(); err != nil {
			return errors.Wrap(err, "could not compile extractor")
		}
	}
	return nil
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
	// OutputExtracts is the list of extracts to be displayed on screen.
	OutputExtracts []string
	// DynamicValues contains any dynamic values to be templated
	DynamicValues map[string]interface{}
	// PayloadValues contains payload values provided by user. (Optional)
	PayloadValues map[string]interface{}
}

// MatchFunc performs matching operation for a matcher on model and returns true or false.
type MatchFunc func(data map[string]interface{}, matcher *matchers.Matcher) bool

// ExtractFunc performs extracting operation for a extractor on model and returns true or false.
type ExtractFunc func(data map[string]interface{}, matcher *extractors.Extractor) map[string]struct{}

// Execute executes the operators on data and returns a result structure
func (r *Operators) Execute(data map[string]interface{}, match MatchFunc, extract ExtractFunc) (*Result, bool) {
	matcherCondition := r.GetMatchersCondition()

	var matches bool
	result := &Result{
		Matches:       make(map[string]struct{}),
		Extracts:      make(map[string][]string),
		DynamicValues: make(map[string]interface{}),
	}
	for _, matcher := range r.Matchers {
		// Check if the matcher matched
		if !match(data, matcher) {
			// If the condition is AND we haven't matched, try next request.
			if matcherCondition == matchers.ANDCondition {
				return nil, false
			}
		} else {
			// If the matcher has matched, and its an OR
			// write the first output then move to next matcher.
			if matcherCondition == matchers.ORCondition && matcher.Name != "" {
				result.Matches[matcher.Name] = struct{}{}
			}
			matches = true
		}
	}

	// All matchers have successfully completed so now start with the
	// next task which is extraction of input from matchers.
	for _, extractor := range r.Extractors {
		var extractorResults []string

		for match := range extract(data, extractor) {
			extractorResults = append(extractorResults, match)

			if extractor.Internal {
				if _, ok := result.DynamicValues[extractor.Name]; !ok {
					result.DynamicValues[extractor.Name] = match
				}
			} else {
				result.OutputExtracts = append(result.OutputExtracts, match)
			}
		}
		if len(extractorResults) > 0 && !extractor.Internal && extractor.Name != "" {
			result.Extracts[extractor.Name] = extractorResults
		}
	}

	// Don't print if we have matchers and they have not matched, irregardless of extractor
	if len(r.Matchers) > 0 && !matches {
		return nil, false
	}
	// Write a final string of output if matcher type is
	// AND or if we have extractors for the mechanism too.
	if len(result.Extracts) > 0 || len(result.DynamicValues) > 0 || len(result.OutputExtracts) > 0 || matches {
		return result, true
	}
	return nil, false
}
