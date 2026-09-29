package templates

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/utils/errkit"
)

// validateLLMSoleMatcher rejects a high or critical template whose request
// relies only on an llm matcher.
//
// An llm verdict is non-deterministic, so it should confirm evidence a cheap
// matcher already found, not be the only thing standing between a target and a
// high-severity finding. A template author who genuinely wants that sets
// allow-sole on the matcher, which makes the choice explicit and reviewable.
func (template *Template) validateLLMSoleMatcher() error {
	sev := template.Info.SeverityHolder.Severity
	if sev != severity.High && sev != severity.Critical {
		return nil
	}

	for _, request := range template.RequestsHTTP {
		if request == nil || len(request.Matchers) == 0 {
			continue
		}

		var hasLLM, hasDeterministic, allowSole bool
		for _, matcher := range request.Matchers {
			if matcher == nil {
				continue
			}
			if matcher.GetType() == matchers.LLMMatcher {
				hasLLM = true
				allowSole = allowSole || matcher.AllowSole
			} else {
				hasDeterministic = true
			}
		}

		if hasLLM && !hasDeterministic && !allowSole {
			return errkit.Newf("template %s is %s severity and its request relies only on an llm matcher; add a deterministic matcher or set allow-sole", template.ID, sev.String())
		}
	}

	return nil
}
