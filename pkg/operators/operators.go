package operators

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/utils/excludematchers"
	sliceutil "github.com/projectdiscovery/utils/slice"
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
	Matchers []*matchers.Matcher `yaml:"matchers,omitempty" json:"matchers,omitempty" jsonschema:"title=matchers to run on response,description=Detection mechanism to identify whether the request was successful by doing pattern matching"`
	// description: |
	//   Extractors contains the extraction mechanism for the request to identify
	//   and extract parts of the response.
	Extractors []*extractors.Extractor `yaml:"extractors,omitempty" json:"extractors,omitempty" jsonschema:"title=extractors to run on response,description=Extractors contains the extraction mechanism for the request to identify and extract parts of the response"`
	// description: |
	//   MatchersCondition is the condition between the matchers. Default is OR.
	// values:
	//   - "and"
	//   - "or"
	MatchersCondition string `yaml:"matchers-condition,omitempty" json:"matchers-condition,omitempty" jsonschema:"title=condition between the matchers,description=Conditions between the matchers,enum=and,enum=or"`
	// cached variables that may be used along with request.
	matchersCondition matchers.ConditionType

	// TemplateID is the ID of the template for matcher
	TemplateID string `json:"-" yaml:"-" jsonschema:"-"`
	// ExcludeMatchers is a list of excludeMatchers items
	ExcludeMatchers *excludematchers.ExcludeMatchers `json:"-" yaml:"-" jsonschema:"-"`
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

func (operators *Operators) HasDSL() bool {
	for _, matcher := range operators.Matchers {
		if len(matcher.DSL) > 0 {
			return true
		}
	}

	for _, extractor := range operators.Extractors {
		if len(extractor.DSL) > 0 {
			return true
		}
	}

	return false
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

	// Optional lineCounts for file protocol
	LineCount string
	// Operators is reference to operators that generated this result (Read-Only)
	Operators *Operators
}

func (result *Result) HasMatch(name string) bool {
	return result.hasItem(name, result.Matches)
}

func (result *Result) HasExtract(name string) bool {
	return result.hasItem(name, result.Extracts)
}

func (result *Result) hasItem(name string, m map[string][]string) bool {
	for matchName := range m {
		if strings.EqualFold(name, matchName) {
			return true
		}
	}
	return false
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
		r.Matches[k] = sliceutil.Dedupe(append(r.Matches[k], v...))
	}
	for k, v := range result.Extracts {
		r.Extracts[k] = sliceutil.Dedupe(append(r.Extracts[k], v...))
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
	for k, v := range result.DynamicValues {
		if _, ok := r.DynamicValues[k]; !ok {
			r.DynamicValues[k] = v
		} else {
			r.DynamicValues[k] = sliceutil.Dedupe(append(r.DynamicValues[k], v...))
		}
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
		Operators:     operators,
	}

	// state variable to check if all extractors are internal
	var allInternalExtractors = true

	// Start with the extractors first and evaluate them.
	for _, extractor := range operators.Extractors {
		if !extractor.Internal && allInternalExtractors {
			allInternalExtractors = false
		}
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
		// update data with whatever was extracted doesn't matter if it is internal or not (skip unless it empty)
		if len(extractorResults) > 0 {
			data[extractor.Name] = getExtractedValue(extractorResults)
		}
	}

	// expose dynamic values to same request matchers
	if len(result.DynamicValues) > 0 {
		dataDynamicValues := make(map[string]interface{})
		for dynName, dynValues := range result.DynamicValues {
			if len(dynValues) > 1 {
				for dynIndex, dynValue := range dynValues {
					dynKeyName := fmt.Sprintf("%s%d", dynName, dynIndex)
					dataDynamicValues[dynKeyName] = dynValue
				}
				dataDynamicValues[dynName] = dynValues
			} else {
				dataDynamicValues[dynName] = dynValues[0]
			}

		}
		data = generators.MergeMaps(data, dataDynamicValues)
	}

	for matcherIndex, matcher := range operators.Matchers {
		// Skip matchers that are in the blocklist
		if operators.ExcludeMatchers != nil {
			if operators.ExcludeMatchers.Match(operators.TemplateID, matcher.Name) {
				continue
			}
		}
		if isMatch, matched := match(data, matcher); isMatch {
			if isDebug { // matchers without an explicit name or with AND condition should only be made visible if debug is enabled
				matcherName := GetMatcherName(matcher, matcherIndex)
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
			return result, false
		}
	}

	result.Matched = matches
	result.Extracted = len(result.OutputExtracts) > 0
	if len(result.DynamicValues) > 0 && allInternalExtractors {
		// only return early if all extractors are internal
		// if some are internal and some are not then followthrough
		return result, true
	}

	// Don't print if we have matchers, and they have not matched, regardless of extractor
	if len(operators.Matchers) > 0 && !matches {
		// if dynamic values are present then it is not a failure
		if len(result.DynamicValues) > 0 {
			return result, true
		}
		return nil, false
	}
	// Write a final string of output if matcher type is
	// AND or if we have extractors for the mechanism too.
	if len(result.Extracts) > 0 || len(result.OutputExtracts) > 0 || matches {
		return result, true
	}
	// if dynamic values are present then it is not a failure
	if len(result.DynamicValues) > 0 {
		return result, true
	}
	return nil, false
}

// GetMatcherName returns matchername of given matcher
func GetMatcherName(matcher *matchers.Matcher, matcherIndex int) string {
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

// IsEmpty determines if the operator has matchers or extractors
func (operators *Operators) IsEmpty() bool {
	return operators.Len() == 0
}

// Len calculates the sum of the number of matchers and extractors
func (operators *Operators) Len() int {
	return len(operators.Matchers) + len(operators.Extractors)
}

// getExtractedValue takes array of extracted values if it only has one value
// then it is flattened and returned as a string else original type is returned
func getExtractedValue(values []string) any {
	if len(values) == 1 {
		return values[0]
	} else {
		return values
	}
}

// EvalBoolSlice evaluates a slice of bools using a logical AND
func EvalBoolSlice(slice []bool, isAnd bool) bool {
	if len(slice) == 0 {
		return false
	}

	result := slice[0]
	for _, b := range slice[1:] {
		if isAnd {
			result = result && b
		} else {
			result = result || b
		}
	}
	return result
}
