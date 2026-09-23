package templates

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	httpProtocol "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/stretchr/testify/require"
)

func tmplWithMatchers(sev severity.Severity, ms ...*matchers.Matcher) *Template {
	return &Template{
		ID:   "t",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: sev}},
		RequestsHTTP: []*httpProtocol.Request{{
			Operators: operators.Operators{Matchers: ms},
		}},
	}
}

func llmM() *matchers.Matcher {
	return &matchers.Matcher{Type: matchers.MatcherTypeHolder{MatcherType: matchers.LLMMatcher}}
}
func wordM() *matchers.Matcher {
	return &matchers.Matcher{Type: matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher}}
}

func TestSoleLLMRejectedOnHigh(t *testing.T) {
	require.ErrorContains(t, tmplWithMatchers(severity.High, llmM()).validateLLMSoleMatcher(), "relies only on an llm matcher")
}

func TestSoleLLMAllowedWithDeterministicMatcher(t *testing.T) {
	require.NoError(t, tmplWithMatchers(severity.Critical, wordM(), llmM()).validateLLMSoleMatcher())
}

func TestSoleLLMAllowedWithOverride(t *testing.T) {
	m := llmM()
	m.AllowSole = true
	require.NoError(t, tmplWithMatchers(severity.Critical, m).validateLLMSoleMatcher())
}

func TestSoleLLMAllowedOnLowSeverity(t *testing.T) {
	require.NoError(t, tmplWithMatchers(severity.Low, llmM()).validateLLMSoleMatcher())
}
