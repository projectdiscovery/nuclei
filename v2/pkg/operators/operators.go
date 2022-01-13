package operators

import (
	"strconv"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
)

// Operators contains the operators that can be applied on protocols
type Operators struct {
	// description: |
	//   Matchers contains the detection mechanism for the request to identify
	//   whether the request was successful by doing pattern matching
	//   on request/responses.
	//
	//   Multiple matchers can be combined with `matcher-condition` flag
	//   which accepts either `and` or `or` as argument.
	Matchers []*matchers.Matcher `yaml:"matchers,omitempty" jsonschema:"title=matchers to run on response,description=Detection mechanism to identify whether the request was successful by doing pattern matching"`
	// description: |
	//   Extractors contains the extraction mechanism for the request to identify
	//   and extract parts of the response.
	Extractors []*extractors.Extractor `yaml:"extractors,omitempty" jsonschema:"title=extractors to run on response,description=Extractors contains the extraction mechanism for the request to identify and extract parts of the response"`
	// description: |
	//   MatchersCondition is the condition between the matchers. Default is OR.
	// values:
	//   - "and"
	//   - "or"
	MatchersCondition string `yaml:"matchers-condition,omitempty" jsonschema:"title=condition between the matchers,description=Conditions between the matchers,enum=and,enum=or"`
	// cached variables that may be used along with request.
	matchersCondition matchers.ConditionType
}

// Compile compiles the operators as well as their corresponding matchers and extractors
func (operators *Operators) Compile() error {
	if operators.MatchersCondition != "" {
		operators.matchersCondition = matchers.ConditionTypes[operators.MatchersCondition]
	} else {
		operators.matchersCondition = matchers.ORCondition
	}

	for _, matcher := range operators.Matchers {
		if err := matcher.CompileMatchers(); err != nil {
			return errors.Wrap(err, "could not compile matcher")
		}
	}
	for _, extractor := range operators.Extractors {
		if err := extractor.CompileExtractors(); err != nil {
			return errors.Wrap(err, "could not compile extractor")
		}
	}
	return nil
}

// GetMatchersCondition returns the condition for the matchers
func (operators *Operators) GetMatchersCondition() matchers.ConditionType {
	return operators.matchersCondition
}

// Result is a result structure created from operators running on data.
type Result struct {
	// Matched is true if any matchers matched
	Matched bool
	// Extracted is true if any result type values were extracted
	Extracted bool
	// Matches is a map of matcher names that we matched
	Matches map[string][]string
	// Extracts contains all the data extracted from inputs
	Extracts map[string][]string
	// OutputExtracts is the list of extracts to be displayed on screen.
	OutputExtracts []string
	outputUnique   map[string]struct{}

	// DynamicValues contains any dynamic values to be templated
	DynamicValues map[string][]string
	// PayloadValues contains payload values provided by user. (Optional)
	PayloadValues map[string]interface{}
}

// MakeDynamicValuesCallback takes an input dynamic values map and calls
// the callback function with all variations of the data in input in form
// of map[string]string (interface{}).
func MakeDynamicValuesCallback(input map[string][]string, iterateAllValues bool, callback func(map[string]interface{}) bool) {
	output := make(map[string]interface{}, len(input))

	if !iterateAllValues {
		for k, v := range input {
			if len(v) > 0 {
				output[k] = v[0]
			}
		}
		callback(output)
		return
	}
	inputIndex := make(map[string]int, len(input))

	var maxValue int
	for _, v := range input {
		if len(v) > maxValue {
			maxValue = len(v)
		}
	}

	for i := 0; i < maxValue; i++ {
		for k, v := range input {
			if len(v) == 0 {
				continue
			}
			if len(v) == 1 {
				output[k] = v[0]
				continue
			}
			if gotIndex, ok := inputIndex[k]; !ok {
				inputIndex[k] = 0
				output[k] = v[0]
			} else {
				newIndex := gotIndex + 1
				if newIndex >= len(v) {
					output[k] = v[len(v)-1]
					continue
				}
				output[k] = v[newIndex]
				inputIndex[k] = newIndex
			}
		}
		// skip if the callback says so
		if callback(output) {
			return
		}
	}
}

// Merge merges a result structure into the other.
func (r *Result) Merge(result *Result) {
	if !r.Matched && result.Matched {
		r.Matched = result.Matched
	}
	if !r.Extracted && result.Extracted {
		r.Extracted = result.Extracted
	}

	for k, v := range result.Matches {
		r.Matches[k] = v
	}
	for k, v := range result.Extracts {
		r.Extracts[k] = v
	}

	r.outputUnique = make(map[string]struct{})
	output := r.OutputExtracts
	r.OutputExtracts = make([]string, 0, len(output))
	for _, v := range output {
		if _, ok := r.outputUnique[v]; !ok {
			r.outputUnique[v] = struct{}{}
			r.OutputExtracts = append(r.OutputExtracts, v)
		}
	}
	for _, v := range result.OutputExtracts {
		if _, ok := r.outputUnique[v]; !ok {
			r.outputUnique[v] = struct{}{}
			r.OutputExtracts = append(r.OutputExtracts, v)
		}
	}
	for _, v := range result.OutputExtracts {
		if _, ok := r.outputUnique[v]; !ok {
			r.outputUnique[v] = struct{}{}
			r.OutputExtracts = append(r.OutputExtracts, v)
		}
	}
	for k, v := range result.DynamicValues {
		r.DynamicValues[k] = v
	}
	for k, v := range result.PayloadValues {
		r.PayloadValues[k] = v
	}
}

// MatchFunc performs matching operation for a matcher on model and returns true or false.
type MatchFunc func(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string)

// ExtractFunc performs extracting operation for an extractor on model and returns true or false.
type ExtractFunc func(data map[string]interface{}, matcher *extractors.Extractor) map[string]struct{}

// Execute executes the operators on data and returns a result structure
func (operators *Operators) Execute(data map[string]interface{}, match MatchFunc, extract ExtractFunc, isDebug bool) (*Result, bool) {
	matcherCondition := operators.GetMatchersCondition()

	var matches bool
	result := &Result{
		Matches:       make(map[string][]string),
		Extracts:      make(map[string][]string),
		DynamicValues: make(map[string][]string),
		outputUnique:  make(map[string]struct{}),
	}

	// Start with the extractors first and evaluate them.
	for _, extractor := range operators.Extractors {
		var extractorResults []string

		for match := range extract(data, extractor) {
			extractorResults = append(extractorResults, match)

			if extractor.Internal {
				if data, ok := result.DynamicValues[extractor.Name]; !ok {
					result.DynamicValues[extractor.Name] = []string{match}
				} else {
					result.DynamicValues[extractor.Name] = append(data, match)
				}
			} else {
				if _, ok := result.outputUnique[match]; !ok {
					result.OutputExtracts = append(result.OutputExtracts, match)
					result.outputUnique[match] = struct{}{}
				}
			}
		}
		if len(extractorResults) > 0 && !extractor.Internal && extractor.Name != "" {
			result.Extracts[extractor.Name] = extractorResults
		}
	}

	for matcherIndex, matcher := range operators.Matchers {
		if isMatch, matched := match(data, matcher); isMatch {
			if isDebug { // matchers without an explicit name or with AND condition should only be made visible if debug is enabled
				matcherName := getMatcherName(matcher, matcherIndex)
				result.Matches[matcherName] = matched
			} else { // if it's a "named" matcher with OR condition, then display it
				if matcherCondition == matchers.ORCondition && matcher.Name != "" {
					result.Matches[matcher.Name] = matched
				}
			}
			matches = true
		} else if matcherCondition == matchers.ANDCondition {
			if len(result.DynamicValues) > 0 {
				return result, true
			}
			return nil, false
		}
	}

	result.Matched = matches
	result.Extracted = len(result.OutputExtracts) > 0
	if len(result.DynamicValues) > 0 {
		return result, true
	}

	// Don't print if we have matchers, and they have not matched, regardless of extractor
	if len(operators.Matchers) > 0 && !matches {
		return nil, false
	}
	// Write a final string of output if matcher type is
	// AND or if we have extractors for the mechanism too.
	if len(result.Extracts) > 0 || len(result.OutputExtracts) > 0 || matches {
		return result, true
	}
	return nil, false
}

func getMatcherName(matcher *matchers.Matcher, matcherIndex int) string {
	if matcher.Name != "" {
		return matcher.Name
	} else {
		return matcher.Type.String() + "-" + strconv.Itoa(matcherIndex+1) // making the index start from 1 to be more readable
	}
}

// ExecuteInternalExtractors executes internal dynamic extractors
func (operators *Operators) ExecuteInternalExtractors(data map[string]interface{}, extract ExtractFunc) map[string]interface{} {
	dynamicValues := make(map[string]interface{})

	// Start with the extractors first and evaluate them.
	for _, extractor := range operators.Extractors {
		if !extractor.Internal {
			continue
		}
		for match := range extract(data, extractor) {
			if _, ok := dynamicValues[extractor.Name]; !ok {
				dynamicValues[extractor.Name] = match
			}
		}
	}
	return dynamicValues
}
