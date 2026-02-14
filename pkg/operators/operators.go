package operators

import (
	"fmt"
	"maps"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/utils/excludematchers"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

// Operators contains the collection of detection and extraction mechanisms
// that can be applied to protocol responses.
type Operators struct {
	// Matchers contains the detection logic to identify successful requests
	// by performing pattern matching on the response data.
	Matchers []*matchers.Matcher `yaml:"matchers,omitempty" json:"matchers,omitempty" jsonschema:"title=matchers to run on response,description=Detection mechanism to identify whether the request was successful"`

	// Extractors contains the logic to capture specific parts of the response.
	Extractors []*extractors.Extractor `yaml:"extractors,omitempty" json:"extractors,omitempty" jsonschema:"title=extractors to run on response,description=Mechanism to identify and extract data from the response"`

	// MatchersCondition defines the logical relationship (AND/OR) between matchers.
	MatchersCondition string `yaml:"matchers-condition,omitempty" json:"matchers-condition,omitempty" jsonschema:"title=condition between the matchers,description=Logical condition between matchers,enum=and,enum=or"`

	matchersCondition matchers.ConditionType

	// TemplateID tracks the source template for filtering and identification.
	TemplateID string `json:"-" yaml:"-" jsonschema:"-"`

	// ExcludeMatchers allows bypassing specific matchers globally or locally.
	ExcludeMatchers *excludematchers.ExcludeMatchers `json:"-" yaml:"-" jsonschema:"-"`
}

const DefaultHoneypotThreshold = 15

var honeypotThreshold atomic.Int64

func init() {
	honeypotThreshold.Store(DefaultHoneypotThreshold)
}

// SetHoneypotThreshold configures the global honeypot detection threshold.
func SetHoneypotThreshold(threshold int) {
	if threshold <= 0 {
		threshold = DefaultHoneypotThreshold
	}
	honeypotThreshold.Store(int64(threshold))
}

// GetHoneypotThreshold returns the effective honeypot detection threshold.
func GetHoneypotThreshold() int {
	threshold := int(honeypotThreshold.Load())
	if threshold <= 0 {
		return DefaultHoneypotThreshold
	}
	return threshold
}

// Compile pre-processes and validates all operators, matchers, and extractors.
func (operators *Operators) Compile() error {
	if operators.MatchersCondition != "" {
		operators.matchersCondition = matchers.ConditionTypes[operators.MatchersCondition]
	} else {
		operators.matchersCondition = matchers.ORCondition
	}

	for _, matcher := range operators.Matchers {
		if err := matcher.CompileMatchers(); err != nil {
			return errors.Wrap(err, "failed to compile matcher")
		}
	}
	for _, extractor := range operators.Extractors {
		if err := extractor.CompileExtractors(); err != nil {
			return errors.Wrap(err, "failed to compile extractor")
		}
	}
	return nil
}

// HasDSL checks if any matcher or extractor within the operator uses Domain Specific Language (DSL).
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

// GetMatchersCondition retrieves the compiled condition type for matchers.
func (operators *Operators) GetMatchersCondition() matchers.ConditionType {
	return operators.matchersCondition
}

// Result encapsulates the outcome of executing operators on a protocol response.
type Result struct {
	// Matched indicates if the overall matching condition was satisfied.
	Matched bool
	// Extracted indicates if any data was successfully captured.
	Extracted bool
	// Matches maps matcher names to the actual strings that triggered them.
	Matches map[string][]string
	// Extracts maps extractor names to the data captured.
	Extracts map[string][]string
	// OutputExtracts contains the flattened list of data to be displayed to the user.
	OutputExtracts []string
	outputUnique   map[string]struct{}

	// DynamicValues stores variables extracted for use in subsequent requests.
	DynamicValues map[string][]string
	// PayloadValues contains user-provided payload data.
	PayloadValues map[string]interface{}

	// LineCount provides line metadata for file-based protocols.
	LineCount string
	// Operators reference the parent operator set that generated this result.
	Operators *Operators

	// HoneypotDetected is a security feature that flags responses that trigger
	// an unusually high number of matchers, typical of anti-scanner honeypots.
	HoneypotDetected bool
}

// HasMatch checks if a specific matcher name exists in the result set.
func (result *Result) HasMatch(name string) bool {
	return result.hasItem(name, result.Matches)
}

// HasExtract checks if a specific extractor name exists in the result set.
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

// Merge combines two Result structures, preserving matches, extracts, and security flags.
func (r *Result) Merge(result *Result) {
	if !r.Matched && result.Matched {
		r.Matched = result.Matched
	}
	if !r.Extracted && result.Extracted {
		r.Extracted = result.Extracted
	}
	// Propagate honeypot detection flag during merge
	if result.HoneypotDetected {
		r.HoneypotDetected = true
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
	maps.Copy(r.PayloadValues, result.PayloadValues)
}

// MatchFunc defines the prototype for performing a match against a dataset.
type MatchFunc func(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string)

// ExtractFunc defines the prototype for performing data extraction from a dataset.
type ExtractFunc func(data map[string]interface{}, matcher *extractors.Extractor) map[string]struct{}

// Execute runs the operator logic (Extraction followed by Matching) against the provided data.
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

	var allInternalExtractors = true

	// PHASE 1: Execution of Extractors
	for _, extractor := range operators.Extractors {
		if !extractor.Internal && allInternalExtractors {
			allInternalExtractors = false
		}
		var extractorResults []string
		for match := range extract(data, extractor) {
			extractorResults = append(extractorResults, match)

			if extractor.Internal {
				result.DynamicValues[extractor.Name] = append(result.DynamicValues[extractor.Name], match)
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
		if len(extractorResults) > 0 {
			data[extractor.Name] = getExtractedValue(extractorResults)
		}
	}

	// Merge extracted dynamic values into the dataset for subsequent matching
	if len(result.DynamicValues) > 0 {
		dataDynamicValues := make(map[string]interface{})
		for dynName, dynValues := range result.DynamicValues {
			if len(dynValues) > 1 {
				for dynIndex, dynValue := range dynValues {
					dataDynamicValues[fmt.Sprintf("%s%d", dynName, dynIndex)] = dynValue
				}
				dataDynamicValues[dynName] = dynValues
			} else {
				dataDynamicValues[dynName] = dynValues[0]
			}
		}
		data = generators.MergeMaps(data, dataDynamicValues)
	}

	// PHASE 2: Execution of Matchers with Honeypot Detection
	matchCount := 0
	for matcherIndex, matcher := range operators.Matchers {
		if operators.ExcludeMatchers != nil && operators.ExcludeMatchers.Match(operators.TemplateID, matcher.Name) {
			continue
		}

		if isMatch, matched := match(data, matcher); isMatch {
			matchCount++
			matcherName := GetMatcherName(matcher, matcherIndex)

			// Store matches based on debug state or naming convention
			if isDebug {
				result.Matches[matcherName] = matched
			} else if matcherCondition == matchers.ORCondition && matcher.Name != "" {
				result.Matches[matcher.Name] = matched
			}
			matches = true
		} else if matcherCondition == matchers.ANDCondition {
			if len(result.DynamicValues) > 0 {
				return result, true
			}
			return result, false
		}
	}

	// SECURITY LOGIC: Honeypot Detection
	// Anti-scanner honeypots often echo back all possible signatures.
	// Triggering an excessive number of matchers (default threshold: 15)
	// indicates a non-genuine response.
	if matchCount > GetHoneypotThreshold() {
		result.HoneypotDetected = true
	}

	result.Matched = matches
	result.Extracted = len(result.OutputExtracts) > 0

	if len(result.DynamicValues) > 0 && allInternalExtractors {
		return result, true
	}

	if len(operators.Matchers) > 0 && !matches {
		if len(result.DynamicValues) > 0 {
			return result, true
		}
		return nil, false
	}

	if len(result.Extracts) > 0 || len(result.OutputExtracts) > 0 || matches {
		return result, true
	}

	if len(result.DynamicValues) > 0 {
		return result, true
	}
	return nil, false
}

// GetMatcherName determines the display name for a matcher based on its definition.
func GetMatcherName(matcher *matchers.Matcher, matcherIndex int) string {
	if matcher.Name != "" {
		return matcher.Name
	}
	return matcher.Type.String() + "-" + strconv.Itoa(matcherIndex+1)
}

// ExecuteInternalExtractors runs only extractors marked as internal.
func (operators *Operators) ExecuteInternalExtractors(data map[string]interface{}, extract ExtractFunc) map[string]interface{} {
	dynamicValues := make(map[string]interface{})
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

// IsEmpty checks if the operator has any active matchers or extractors.
func (operators *Operators) IsEmpty() bool {
	return operators.Len() == 0
}

// Len returns the total count of matchers and extractors.
func (operators *Operators) Len() int {
	return len(operators.Matchers) + len(operators.Extractors)
}

func getExtractedValue(values []string) any {
	if len(values) == 1 {
		return values[0]
	}
	return values
}

// EvalBoolSlice performs a logical evaluation of a boolean slice.
func EvalBoolSlice(slice []bool, isAnd bool) bool {
	if len(slice) == 0 {
		return false
	}
	res := slice[0]
	for _, b := range slice[1:] {
		if isAnd {
			res = res && b
		} else {
			res = res || b
		}
	}
	return res
}

// MakeDynamicValuesCallback iterates dynamic values and invokes callback with each generated dataset.
func MakeDynamicValuesCallback(input map[string][]string, iterateAll bool, callback func(data map[string]interface{}) bool) {
	keys := make([]string, 0, len(input))
	for key, values := range input {
		if len(values) > 0 {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)

	if len(keys) == 0 {
		_ = callback(map[string]interface{}{})
		return
	}

	iterations := 1
	if iterateAll {
		for _, key := range keys {
			if l := len(input[key]); l > iterations {
				iterations = l
			}
		}
	}

	for i := 0; i < iterations; i++ {
		data := make(map[string]interface{}, len(keys))
		for _, key := range keys {
			values := input[key]
			idx := 0
			if iterateAll {
				idx = i
				if idx >= len(values) {
					idx = len(values) - 1
				}
			}
			data[key] = values[idx]
		}
		if callback(data) {
			return
		}
	}
}
