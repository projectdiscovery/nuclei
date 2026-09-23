package templates

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/dns"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/network"
	"github.com/stretchr/testify/require"
)

func llmMatcherOperators() operators.Operators {
	return operators.Operators{
		Matchers: []*matchers.Matcher{
			{Type: matchers.MatcherTypeHolder{MatcherType: matchers.LLMMatcher}, Prompt: "is this vulnerable?"},
		},
	}
}

func TestValidateLLMProtocolSupportRejectsNonHTTPMatcher(t *testing.T) {
	template := &Template{ID: "llm-on-dns"}
	template.RequestsDNS = []*dns.Request{{Operators: llmMatcherOperators()}}
	template.RequestsDNS[0].CompiledOperators = &template.RequestsDNS[0].Operators

	err := template.validateLLMProtocolSupport()
	require.ErrorContains(t, err, "llm matcher")
	require.ErrorContains(t, err, "dns")
}

func TestValidateLLMProtocolSupportRejectsNonHTTPExtractor(t *testing.T) {
	template := &Template{ID: "llm-on-network"}
	request := &network.Request{Operators: operators.Operators{
		Extractors: []*extractors.Extractor{
			{Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.LLMExtractor}, Name: "version"},
		},
	}}
	request.CompiledOperators = &request.Operators
	template.RequestsNetwork = []*network.Request{request}

	err := template.validateLLMProtocolSupport()
	require.ErrorContains(t, err, "llm extractor")
	require.ErrorContains(t, err, "network")
}

func TestValidateLLMProtocolSupportAllowsNonLLMOperators(t *testing.T) {
	template := &Template{ID: "plain-dns"}
	request := &dns.Request{Operators: operators.Operators{
		Matchers: []*matchers.Matcher{
			{Type: matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher}, Words: []string{"ok"}},
		},
	}}
	request.CompiledOperators = &request.Operators
	template.RequestsDNS = []*dns.Request{request}

	require.NoError(t, template.validateLLMProtocolSupport())
}
