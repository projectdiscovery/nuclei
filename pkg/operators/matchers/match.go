package matchers

import (
	"os"
	"strings"

	"github.com/Knetic/govaluate"
	"github.com/antchfx/htmlquery"
	"github.com/antchfx/xmlquery"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/expressions"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

var (
	// showDSLErr controls whether to show hidden DSL errors or not
	showDSLErr = strings.EqualFold(os.Getenv("SHOW_DSL_ERRORS"), "true")
)

// maxRegexScanBytes limits the number of bytes scanned by regex to avoid excessive CPU on huge bodies.
const maxRegexScanBytes = 4 << 20 // 4 MiB

// MatchStatusCode matches a status code check against a corpus
func (matcher *Matcher) MatchStatusCode(statusCode int) bool {
	// Iterate over all the status codes accepted as valid
	//
	// Status codes don't support AND conditions.
	for _, status := range matcher.Status {
		// Continue if the status codes don't match
		if statusCode != status {
			continue
		}
		// Return on the first match.
		return true
	}
	return false
}

// MatchSize matches a size check against a corpus
func (matcher *Matcher) MatchSize(length int) bool {
	// Iterate over all the sizes accepted as valid
	//
	// Sizes codes don't support AND conditions.
	for _, size := range matcher.Size {
		// Continue if the size doesn't match
		if length != size {
			continue
		}
		// Return on the first match.
		return true
	}
	return false
}

// MatchWords matches a word check against a corpus.
func (matcher *Matcher) MatchWords(corpus string, data map[string]interface{}) (bool, []string) {
	if matcher.CaseInsensitive {
		corpus = strings.ToLower(corpus)
	}

	var matchedWords []string
	// Iterate over all the words accepted as valid
	for i, word := range matcher.Words {
		if data == nil {
			data = make(map[string]interface{})
		}

		var err error
		word, err = expressions.Evaluate(word, data)
		if err != nil {
			gologger.Warning().Msgf("Error while evaluating word matcher: %q", word)
			if matcher.condition == ANDCondition {
				return false, []string{}
			}
		}
		// Continue if the word doesn't match
		if !strings.Contains(corpus, word) {
			// If we are in an AND request and a match failed,
			// return false as the AND condition fails on any single mismatch.
			switch matcher.condition {
			case ANDCondition:
				return false, []string{}
			case ORCondition:
				continue
			}
		}

		// If the condition was an OR, return on the first match.
		if matcher.condition == ORCondition && !matcher.MatchAll {
			return true, []string{word}
		}
		matchedWords = append(matchedWords, word)

		// If we are at the end of the words, return with true
		if len(matcher.Words)-1 == i && !matcher.MatchAll {
			return true, matchedWords
		}
	}
	if len(matchedWords) > 0 && matcher.MatchAll {
		return true, matchedWords
	}
	return false, []string{}
}

// MatchRegex matches a regex check against a corpus
func (matcher *Matcher) MatchRegex(corpus string) (bool, []string) {
	var matchedRegexes []string
	// Iterate over all the regexes accepted as valid
	for i, regex := range matcher.regexCompiled {
		// Literal prefix short-circuit to avoid regex engine when clearly absent
		if prefix, ok := regex.LiteralPrefix(); ok && prefix != "" {
			if !strings.Contains(corpus, prefix) {
				switch matcher.condition {
				case ANDCondition:
					return false, []string{}
				case ORCondition:
					continue
				}
			}
		}

		// Fast OR-path: return first match without full scan
		if matcher.condition == ORCondition && !matcher.MatchAll {
			m := regex.FindString(corpus)
			if m == "" {
				continue
			}
			return true, []string{m}
		}

		// Single scan: get all matches, and decide based on condition
		currentMatches := regex.FindAllString(corpus, -1)
		if len(currentMatches) == 0 {
			switch matcher.condition {
			case ANDCondition:
				return false, []string{}
			case ORCondition:
				continue
			}
		}

		// If the condition was an OR (and MatchAll true), we still need to gather all
		matchedRegexes = append(matchedRegexes, currentMatches...)

		// If we are at the end of the regex, return with true
		if len(matcher.regexCompiled)-1 == i && !matcher.MatchAll {
			return true, matchedRegexes
		}
	}
	if len(matchedRegexes) > 0 && matcher.MatchAll {
		return true, matchedRegexes
	}
	return false, []string{}
}

// MatchBinary matches a binary check against a corpus
func (matcher *Matcher) MatchBinary(corpus string) (bool, []string) {
	var matchedBinary []string
	// Iterate over all the words accepted as valid
	for i, binary := range matcher.binaryDecoded {
		if !strings.Contains(corpus, binary) {
			// If we are in an AND request and a match failed,
			// return false as the AND condition fails on any single mismatch.
			switch matcher.condition {
			case ANDCondition:
				return false, []string{}
			case ORCondition:
				continue
			}
		}

		// If the condition was an OR, return on the first match.
		if matcher.condition == ORCondition {
			return true, []string{binary}
		}

		matchedBinary = append(matchedBinary, binary)

		// If we are at the end of the words, return with true
		if len(matcher.Binary)-1 == i {
			return true, matchedBinary
		}
	}
	return false, []string{}
}

// MatchDSL matches on a generic map result
func (matcher *Matcher) MatchDSL(data map[string]interface{}) bool {
	logExpressionEvaluationFailure := func(matcherName string, err error) {
		gologger.Warning().Msgf("Could not evaluate expression: %s, error: %s", matcherName, err.Error())
	}

	// Iterate over all the expressions accepted as valid
	for i, expression := range matcher.dslCompiled {
		if varErr := expressions.ContainsUnresolvedVariables(expression.String()); varErr != nil {
			resolvedExpression, err := expressions.Evaluate(expression.String(), data)
			if err != nil {
				logExpressionEvaluationFailure(matcher.Name, err)
				return false
			}
			expression, err = govaluate.NewEvaluableExpressionWithFunctions(resolvedExpression, dsl.HelperFunctions)
			if err != nil {
				logExpressionEvaluationFailure(matcher.Name, err)
				return false
			}
		}

		result, err := expression.Evaluate(data)
		if err != nil {
			if matcher.condition == ANDCondition {
				return false
			}
			if !matcher.ignoreErr(err) {
				gologger.Warning().Msgf("[%s] %s", data["template-id"], err.Error())
			}
			continue
		}

		if boolResult, ok := result.(bool); !ok {
			gologger.Error().Label("WRN").Msgf("[%s] The return value of a DSL statement must return a boolean value.", data["template-id"])
			continue
		} else if !boolResult {
			// If we are in an AND request and a match failed,
			// return false as the AND condition fails on any single mismatch.
			switch matcher.condition {
			case ANDCondition:
				return false
			case ORCondition:
				continue
			}
		}

		// If the condition was an OR, return on the first match.
		if matcher.condition == ORCondition {
			return true
		}

		// If we are at the end of the dsl, return with true
		if len(matcher.dslCompiled)-1 == i {
			return true
		}
	}
	return false
}

// MatchXPath matches on a generic map result
func (matcher *Matcher) MatchXPath(corpus string) bool {
	if strings.HasPrefix(corpus, "<?xml") {
		return matcher.MatchXML(corpus)
	}
	return matcher.MatchHTML(corpus)
}

// MatchHTML matches items from HTML using XPath selectors
func (matcher *Matcher) MatchHTML(corpus string) bool {
	doc, err := htmlquery.Parse(strings.NewReader(corpus))
	if err != nil {
		return false
	}

	matches := 0

	for _, k := range matcher.XPath {
		nodes, err := htmlquery.QueryAll(doc, k)
		if err != nil {
			continue
		}

		// Continue if the xpath doesn't return any nodes
		if len(nodes) == 0 {
			// If we are in an AND request and a match failed,
			// return false as the AND condition fails on any single mismatch.
			switch matcher.condition {
			case ANDCondition:
				return false
			case ORCondition:
				continue
			}
		}

		// If the condition was an OR, return on the first match.
		if matcher.condition == ORCondition && !matcher.MatchAll {
			return true
		}

		matches = matches + len(nodes)
	}
	return matches > 0
}

// MatchXML matches items from XML using XPath selectors
func (matcher *Matcher) MatchXML(corpus string) bool {
	doc, err := xmlquery.Parse(strings.NewReader(corpus))
	if err != nil {
		return false
	}

	matches := 0

	for _, k := range matcher.XPath {
		nodes, err := xmlquery.QueryAll(doc, k)
		if err != nil {
			continue
		}

		// Continue if the xpath doesn't return any nodes
		if len(nodes) == 0 {
			// If we are in an AND request and a match failed,
			// return false as the AND condition fails on any single mismatch.
			switch matcher.condition {
			case ANDCondition:
				return false
			case ORCondition:
				continue
			}
		}

		// If the condition was an OR, return on the first match.
		if matcher.condition == ORCondition && !matcher.MatchAll {
			return true
		}
		matches = matches + len(nodes)
	}

	return matches > 0
}

// ignoreErr checks if the error is to be ignored or not
// Reference: https://github.com/projectdiscovery/nuclei/issues/3950
func (m *Matcher) ignoreErr(err error) bool {
	if showDSLErr {
		return false
	}
	if stringsutil.ContainsAny(err.Error(), "No parameter", "error parsing argument value") {
		return true
	}
	return false
}
