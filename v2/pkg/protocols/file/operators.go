package file

import (
	"bufio"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Match matches a generic data response again a given matcher
func (request *Request) Match(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
	itemStr, ok := request.getMatchPart(matcher.Part, data)
	if !ok && matcher.Type.MatcherType != matchers.DSLMatcher {
		return false, []string{}
	}

	switch matcher.GetType() {
	case matchers.SizeMatcher:
		return matcher.Result(matcher.MatchSize(len(itemStr))), []string{}
	case matchers.WordsMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchWords(itemStr, nil))
	case matchers.RegexMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchRegex(itemStr))
	case matchers.BinaryMatcher:
		return matcher.ResultWithMatchedSnippet(matcher.MatchBinary(itemStr))
	case matchers.DSLMatcher:
		return matcher.Result(matcher.MatchDSL(data)), []string{}
	}
	return false, []string{}
}

// Extract performs extracting operation for an extractor on model and returns true or false.
func (request *Request) Extract(data map[string]interface{}, extractor *extractors.Extractor) map[string]struct{} {
	itemStr, ok := request.getMatchPart(extractor.Part, data)
	if !ok && extractor.Type.ExtractorType != extractors.KValExtractor {
		return nil
	}

	switch extractor.GetType() {
	case extractors.RegexExtractor:
		return extractor.ExtractRegex(itemStr)
	case extractors.KValExtractor:
		return extractor.ExtractKval(data)
	}
	return nil
}

func (request *Request) getMatchPart(part string, data output.InternalEvent) (string, bool) {
	switch part {
	case "body", "all", "data", "":
		part = "raw"
	}

	item, ok := data[part]
	if !ok {
		return "", false
	}
	itemStr := types.ToString(item)

	return itemStr, true
}

// responseToDSLMap converts a file response to a map for use in DSL matching
func (request *Request) responseToDSLMap(raw, inputFilePath, matchedFileName string) output.InternalEvent {
	return output.InternalEvent{
		"path":          inputFilePath,
		"matched":       matchedFileName,
		"raw":           raw,
		"type":          request.Type().String(),
		"template-id":   request.options.TemplateID,
		"template-info": request.options.TemplateInfo,
		"template-path": request.options.TemplatePath,
	}
}

// MakeResultEvent creates a result event from internal wrapped event
func (request *Request) MakeResultEvent(wrapped *output.InternalWrappedEvent) []*output.ResultEvent {
	results := protocols.MakeDefaultResultEvent(request, wrapped)

	raw, ok := wrapped.InternalEvent["raw"]
	if !ok {
		return results
	}

	rawStr, ok := raw.(string)
	if !ok {
		return results
	}

	// Identify the position of match in file using a dirty hack.
	for _, result := range results {
		for _, extraction := range result.ExtractedResults {
			scanner := bufio.NewScanner(strings.NewReader(rawStr))

			line := 1
			for scanner.Scan() {
				if strings.Contains(scanner.Text(), extraction) {
					if result.FileToIndexPosition == nil {
						result.FileToIndexPosition = make(map[string]int)
					}
					result.FileToIndexPosition[result.Matched] = line
					continue
				}
				line++
			}
		}
	}
	return results
}

func (request *Request) GetCompiledOperators() []*operators.Operators {
	return []*operators.Operators{request.CompiledOperators}
}

func (request *Request) MakeResultEventItem(wrapped *output.InternalWrappedEvent) *output.ResultEvent {
	data := &output.ResultEvent{
		MatcherStatus:    true,
		TemplateID:       types.ToString(wrapped.InternalEvent["template-id"]),
		TemplatePath:     types.ToString(wrapped.InternalEvent["template-path"]),
		Info:             wrapped.InternalEvent["template-info"].(model.Info),
		Type:             types.ToString(wrapped.InternalEvent["type"]),
		Path:             types.ToString(wrapped.InternalEvent["path"]),
		Matched:          types.ToString(wrapped.InternalEvent["matched"]),
		Host:             types.ToString(wrapped.InternalEvent["host"]),
		ExtractedResults: wrapped.OperatorsResult.OutputExtracts,
		Response:         types.ToString(wrapped.InternalEvent["raw"]),
		Timestamp:        time.Now(),
	}
	return data
}
