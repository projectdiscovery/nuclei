package matchers

import (
	"regexp"

	"github.com/Knetic/govaluate"
)

// Matcher is used to match a part in the output from a protocol.
type Matcher struct {
	// description: |
	//   Type is the type of the matcher.
	Type MatcherTypeHolder `yaml:"type" json:"type" jsonschema:"title=type of matcher,description=Type of the matcher,enum=status,enum=size,enum=word,enum=regex,enum=binary,enum=dsl"`
	// description: |
	//   Condition is the optional condition between two matcher variables. By default,
	//   the condition is assumed to be OR.
	// values:
	//   - "and"
	//   - "or"
	Condition string `yaml:"condition,omitempty" json:"condition,omitempty" jsonschema:"title=condition between matcher variables,description=Condition between the matcher variables,enum=and,enum=or"`

	// description: |
	//   Part is the part of the request response to match data from.
	//
	//   Each protocol exposes a lot of different parts which are well
	//   documented in docs for each request type.
	// examples:
	//   - value: "\"body\""
	//   - value: "\"raw\""
	Part string `yaml:"part,omitempty" json:"part,omitempty" jsonschema:"title=part of response to match,description=Part of response to match data from"`

	// description: |
	//   Negative specifies if the match should be reversed
	//   It will only match if the condition is not true.
	Negative bool `yaml:"negative,omitempty" json:"negative,omitempty" jsonschema:"title=negative specifies if match reversed,description=Negative specifies if the match should be reversed. It will only match if the condition is not true"`

	// description: |
	//   Name of the matcher. Name should be lowercase and must not contain
	//   spaces or underscores (_).
	// examples:
	//   - value: "\"cookie-matcher\""
	Name string `yaml:"name,omitempty" json:"name,omitempty" jsonschema:"title=name of the matcher,description=Name of the matcher"`
	// description: |
	//   Status are the acceptable status codes for the response.
	// examples:
	//   - value: >
	//       []int{200, 302}
	Status []int `yaml:"status,omitempty" json:"status,omitempty" jsonschema:"title=status to match,description=Status to match for the response"`
	// description: |
	//   Size is the acceptable size for the response
	// examples:
	//   - value: >
	//       []int{3029, 2042}
	Size []int `yaml:"size,omitempty" json:"size,omitempty" jsonschema:"title=acceptable size for response,description=Size is the acceptable size for the response"`
	// description: |
	//   Words contains word patterns required to be present in the response part.
	// examples:
	//   - name: Match for Outlook mail protection domain
	//     value: >
	//       []string{"mail.protection.outlook.com"}
	//   - name: Match for application/json in response headers
	//     value: >
	//       []string{"application/json"}
	Words []string `yaml:"words,omitempty" json:"words,omitempty" jsonschema:"title=words to match in response,description= Words contains word patterns required to be present in the response part"`
	// description: |
	//   Regex contains Regular Expression patterns required to be present in the response part.
	// examples:
	//   - name: Match for Linkerd Service via Regex
	//     value: >
	//       []string{`(?mi)^Via\\s*?:.*?linkerd.*$`}
	//   - name: Match for Open Redirect via Location header
	//     value: >
	//       []string{`(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_\\.@]*)example\\.com.*$`}
	Regex []string `yaml:"regex,omitempty" json:"regex,omitempty" jsonschema:"title=regex to match in response,description=Regex contains regex patterns required to be present in the response part"`
	// description: |
	//   Binary are the binary patterns required to be present in the response part.
	// examples:
	//   - name: Match for Springboot Heapdump Actuator "JAVA PROFILE", "HPROF", "Gunzip magic byte"
	//     value: >
	//       []string{"4a4156412050524f46494c45", "4850524f46", "1f8b080000000000"}
	//   - name: Match for 7zip files
	//     value: >
	//       []string{"377ABCAF271C"}
	Binary []string `yaml:"binary,omitempty" json:"binary,omitempty" jsonschema:"title=binary patterns to match in response,description=Binary are the binary patterns required to be present in the response part"`
	// description: |
	//   DSL are the dsl expressions that will be evaluated as part of nuclei matching rules.
	//   A list of these helper functions are available [here](https://nuclei.projectdiscovery.io/templating-guide/helper-functions/).
	// examples:
	//   - name: DSL Matcher for package.json file
	//     value: >
	//       []string{"contains(body, 'packages') && contains(tolower(all_headers), 'application/octet-stream') && status_code == 200"}
	//   - name: DSL Matcher for missing strict transport security header
	//     value: >
	//       []string{"!contains(tolower(all_headers), ''strict-transport-security'')"}
	DSL []string `yaml:"dsl,omitempty" json:"dsl,omitempty" jsonschema:"title=dsl expressions to match in response,description=DSL are the dsl expressions that will be evaluated as part of nuclei matching rules"`
	// description: |
	//   XPath are the xpath queries expressions that will be evaluated against the response part.
	// examples:
	//   - name: XPath Matcher to check a title
	//     value: >
	//       []string{"/html/head/title[contains(text(), 'How to Find XPath')]"}
	//   - name: XPath Matcher for finding links with target="_blank"
	//     value: >
	//       []string{"//a[@target="_blank"]"}
	XPath []string `yaml:"xpath,omitempty" json:"xpath,omitempty" jsonschema:"title=xpath queries to match in response,description=xpath are the XPath queries that will be evaluated against the response part of nuclei matching rules"`
	// description: |
	//   Encoding specifies the encoding for the words field if any.
	// values:
	//   - "hex"
	Encoding string `yaml:"encoding,omitempty" json:"encoding,omitempty" jsonschema:"title=encoding for word field,description=Optional encoding for the word fields,enum=hex"`
	// description: |
	//   CaseInsensitive enables case-insensitive matches. Default is false.
	// values:
	//   - false
	//   - true
	CaseInsensitive bool `yaml:"case-insensitive,omitempty" json:"case-insensitive,omitempty" jsonschema:"title=use case insensitive match,description=use case insensitive match"`
	// description: |
	//   MatchAll enables matching for all matcher values. Default is false.
	// values:
	//   - false
	//   - true
	MatchAll bool `yaml:"match-all,omitempty" json:"match-all,omitempty" jsonschema:"title=match all values,description=match all matcher values ignoring condition"`

	// cached data for the compiled matcher
	condition     ConditionType // todo: this field should be the one used for overridden marshal ops
	matcherType   MatcherType
	binaryDecoded []string
	regexCompiled []*regexp.Regexp
	dslCompiled   []*govaluate.EvaluableExpression
}

// ConditionType is the type of condition for matcher
type ConditionType int

const (
	// ANDCondition matches responses with AND condition in arguments.
	ANDCondition ConditionType = iota + 1
	// ORCondition matches responses with AND condition in arguments.
	ORCondition
)

// ConditionTypes is a table for conversion of condition type from string.
var ConditionTypes = map[string]ConditionType{
	"and": ANDCondition,
	"or":  ORCondition,
}

// Result reverts the results of the match if the matcher is of type negative.
func (matcher *Matcher) Result(data bool) bool {
	if matcher.Negative {
		return !data
	}
	return data
}

// ResultWithMatchedSnippet returns true and the matched snippet, or false and an empty string
func (matcher *Matcher) ResultWithMatchedSnippet(data bool, matchedSnippet []string) (bool, []string) {
	if matcher.Negative {
		return !data, []string{}
	}
	return data, matchedSnippet
}
