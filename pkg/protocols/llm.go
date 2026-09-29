package protocols

import (
	"maps"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/marker"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/replacer"
)

// LLMAuditKey holds the per-response llm audits inside the event data. It is
// read back when the result event is built and never copied into output.
const LLMAuditKey = matchers.AuditEventKey

// targetValueKeys are the target-derived values an llm prompt may interpolate.
// They are the keys shared by every protocol's event map; a protocol that does
// not set one simply contributes nothing for it.
var targetValueKeys = []string{"BaseURL", "RootURL", "Hostname", "Host", "Port", "Scheme", "Path", "Input", "Type"}

// LLMPromptValues returns the values an llm prompt may interpolate: the
// template variables, -var and constants the operator declared, plus the
// target. Declared values come from those maps, not the merged response
// event, so a colliding body, header, or extractor cannot overwrite them.
// Placeholders inside declared strings are resolved against the target only.
//
// Response derived values (body, headers, extracted fields) are deliberately
// excluded. They are attacker influenced, and putting them in the instruction
// is what framing the response keeps them out of.
func LLMPromptValues(e *ExecutorOptions, data map[string]interface{}) map[string]interface{} {
	values := make(map[string]interface{})
	if e == nil {
		return values
	}

	targets := make(map[string]interface{})
	for _, key := range targetValueKeys {
		if value, ok := data[key]; ok {
			targets[key] = value
		}
	}

	declared := func(src map[string]interface{}) {
		for name, value := range src {
			if str, ok := value.(string); ok {
				values[name] = replacer.Replace(str, targets)
			} else {
				values[name] = value
			}
		}
	}
	declared(e.Variables.GetAll())
	declared(e.Constants)
	if e.Options != nil {
		declared(e.Options.Vars.AsMap())
	}
	maps.Copy(values, targets)
	return values
}

// ResolveLLMInputs resolves the responses an inputs matcher compares. Unlike
// the prompt, these are corpora: they are framed as data, so resolving them
// from the whole event, response values included, is what the field is for.
// It returns false when a placeholder has no value yet, which happens on the
// responses before the last one: sending the literal placeholder would spend a
// model call on a question that cannot be answered.
func ResolveLLMInputs(inputs []string, data map[string]interface{}) ([]string, bool) {
	if len(inputs) == 0 {
		return nil, true
	}
	resolved := make([]string, 0, len(inputs))
	for _, input := range inputs {
		value, ok := resolveLLMInput(input, data)
		if !ok {
			return nil, false
		}
		resolved = append(resolved, value)
	}
	return resolved, true
}

// resolveLLMInput interpolates only the placeholders written in the input
// template. Response text is left opaque, so a body that happens to contain
// "{{" or "§" is not treated as an unresolved marker and is not scanned for
// further substitutions.
func resolveLLMInput(input string, data map[string]interface{}) (string, bool) {
	values := make(map[string]interface{})
	for _, key := range llmInputPlaceholders(input) {
		value, ok := data[key]
		if !ok {
			return "", false
		}
		values[key] = value
	}
	return replacer.Replace(input, values), true
}

func llmInputPlaceholders(input string) []string {
	keys := collectMarkers(input, marker.ParenthesisOpen, marker.ParenthesisClose)
	return append(keys, collectMarkers(input, marker.General, marker.General)...)
}

func collectMarkers(input, open, close string) []string {
	var keys []string
	for start := 0; start < len(input); {
		from := strings.Index(input[start:], open)
		if from < 0 {
			break
		}
		from += start + len(open)
		to := strings.Index(input[from:], close)
		if to < 0 {
			break
		}
		if key := input[from : from+to]; key != "" {
			keys = append(keys, key)
		}
		start = from + to + len(close)
	}
	return keys
}

// BindLLMOperators injects the scan's llm client into every llm matcher and
// extractor of a compiled operator set, and reports whether it found any.
//
// Binding is what makes an llm operator run at all: without a client every llm
// path returns a negative result rather than an error, so a protocol that skips
// this reports nothing instead of failing.
func BindLLMOperators(compiled *operators.Operators, e *ExecutorOptions) bool {
	if compiled == nil || e == nil {
		return false
	}
	var found bool
	for _, matcher := range compiled.Matchers {
		if matcher != nil && matcher.GetType() == matchers.LLMMatcher {
			matcher.SetLLMClient(e.LLMClient)
			found = true
		}
	}
	for _, extractor := range compiled.Extractors {
		if extractor != nil && extractor.GetType() == extractors.LLMExtractor {
			extractor.SetLLMClient(e.LLMClient)
			found = true
		}
	}
	return found
}

// RecordLLMAudit stores an audit under the matcher's name, so a response with
// several llm matchers keeps them apart. It creates the map on first use as a
// fallback; operators.Execute seeds it before MergeMaps so the caller's
// InternalEvent still sees audits when dynamic extractors ran.
func RecordLLMAudit(data map[string]interface{}, matcher *matchers.Matcher, audit *matchers.LLMAudit) {
	if data == nil {
		return
	}
	audits, ok := data[LLMAuditKey].(map[string]*matchers.LLMAudit)
	if !ok {
		audits = make(map[string]*matchers.LLMAudit)
		data[LLMAuditKey] = audits
	}
	audits[matcher.Name] = audit
}

// LLMAuditFor returns the audit belonging to the named matcher, falling back to
// the only audit present when the event carries no matcher name.
func LLMAuditFor(data map[string]interface{}, matcherName string) *matchers.LLMAudit {
	audits, ok := data[LLMAuditKey].(map[string]*matchers.LLMAudit)
	if !ok || len(audits) == 0 {
		return nil
	}
	if audit, ok := audits[matcherName]; ok {
		return audit
	}
	if len(audits) == 1 {
		for _, audit := range audits {
			return audit
		}
	}
	return nil
}

// AttachLLMAudits copies the audit each result's matcher produced onto it. It
// runs after the default builder has split the results, since that is when the
// matcher name a result belongs to is assigned.
func AttachLLMAudits(results []*output.ResultEvent, data map[string]interface{}) []*output.ResultEvent {
	for _, result := range results {
		if audit := LLMAuditFor(data, result.MatcherName); audit != nil {
			result.LLM = audit
		}
	}
	return results
}

// MatchLLM evaluates an llm matcher against the event. item is the matcher's
// part, already resolved by the calling protocol, and is used when the matcher
// compares a single response rather than several via inputs.
func MatchLLM(data map[string]interface{}, matcher *matchers.Matcher, item string, e *ExecutorOptions) (bool, []string) {
	inputs, ok := ResolveLLMInputs(matcher.Inputs, data)
	if !ok {
		return false, []string{}
	}
	isMatch, snippets, audit := matcher.MatchLLMWithAudit(item, inputs, LLMPromptValues(e, data))
	// The audit rides on the per-response event data until the result event is
	// built; matchers are shared across concurrent requests, so it cannot be
	// parked on the matcher itself.
	if audit != nil {
		RecordLLMAudit(data, matcher, audit)
	}
	return matcher.ResultWithMatchedSnippet(isMatch, snippets)
}

// ExtractLLM evaluates an llm extractor against the resolved part.
func ExtractLLM(data map[string]interface{}, extractor *extractors.Extractor, item string, e *ExecutorOptions) map[string]struct{} {
	return extractor.ExtractLLM(item, LLMPromptValues(e, data))
}
