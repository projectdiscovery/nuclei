package templates

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/utils/errkit"
)

// operatorHolder is implemented by every protocol request.
type operatorHolder interface {
	GetCompiledOperators() []*operators.Operators
}

// validateLLMProtocolSupport rejects llm matchers and extractors on protocols
// that cannot evaluate them.
//
// Only the http protocol calls MatchLLM and ExtractLLM. An llm operator on any
// other protocol compiles cleanly and then never runs, so the template silently
// reports nothing instead of failing. Erroring at compile time is the honest
// answer until the remaining protocols are wired.
func (template *Template) validateLLMProtocolSupport() error {
	unsupported := map[string][]operatorHolder{
		"dns":        asOperatorHolders(template.RequestsDNS),
		"file":       asOperatorHolders(template.RequestsFile),
		"network":    asOperatorHolders(template.RequestsNetwork),
		"headless":   asOperatorHolders(template.RequestsHeadless),
		"ssl":        asOperatorHolders(template.RequestsSSL),
		"websocket":  asOperatorHolders(template.RequestsWebsocket),
		"whois":      asOperatorHolders(template.RequestsWHOIS),
		"code":       asOperatorHolders(template.RequestsCode),
		"javascript": asOperatorHolders(template.RequestsJavascript),
	}

	for protocol, requests := range unsupported {
		for _, request := range requests {
			if request == nil {
				continue
			}
			for _, operator := range request.GetCompiledOperators() {
				if operator == nil {
					continue
				}
				if kind := llmOperatorKind(operator); kind != "" {
					return errkit.Newf("template %s uses an llm %s on the %s protocol, which does not evaluate llm operators; only http is supported", template.ID, kind, protocol)
				}
			}
		}
	}

	return nil
}

// llmOperatorKind names the first llm operator found, or returns an empty
// string when there is none.
func llmOperatorKind(operator *operators.Operators) string {
	for _, matcher := range operator.Matchers {
		if matcher != nil && matcher.GetType() == matchers.LLMMatcher {
			return "matcher"
		}
	}
	for _, extractor := range operator.Extractors {
		if extractor != nil && extractor.GetType() == extractors.LLMExtractor {
			return "extractor"
		}
	}
	return ""
}

func asOperatorHolders[T operatorHolder](requests []T) []operatorHolder {
	holders := make([]operatorHolder, 0, len(requests))
	for _, request := range requests {
		holders = append(holders, request)
	}
	return holders
}
