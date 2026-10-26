package protocols

import (
	"context"
	"testing"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/variables"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestLLMPromptValuesExcludeResponseDerivedValues(t *testing.T) {
	executerOpts := &ExecutorOptions{
		Constants: map[string]interface{}{"focus_area": "Authentication"},
		Options:   &types.Options{Vars: goflags.RuntimeMap{}},
	}

	data := map[string]interface{}{
		"BaseURL":    "https://acme.test",
		"Hostname":   "acme.test",
		"focus_area": "Authentication",
		"body":       "<html>attacker controlled</html>",
		"csrf_token": "extracted-from-response",
	}

	values := LLMPromptValues(executerOpts, data)
	require.Equal(t, "https://acme.test", values["BaseURL"])
	require.Equal(t, "acme.test", values["Hostname"])
	require.Equal(t, "Authentication", values["focus_area"], "constants the operator declared are interpolated")
	require.NotContains(t, values, "body", "the response body must never reach the instruction")
	require.NotContains(t, values, "csrf_token", "response derived values must never reach the instruction")
}

func TestLLMPromptValuesIgnoreResponseCollisions(t *testing.T) {
	templateVars := variables.Variable{
		InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(2),
	}
	templateVars.Set("body", "operator-body")
	templateVars.Set("role", "auditor for {{BaseURL}}")

	options := &types.Options{Vars: goflags.RuntimeMap{}}
	require.NoError(t, options.Vars.Set("cli_role=from-var"))

	executerOpts := &ExecutorOptions{
		Variables: templateVars,
		Constants: map[string]interface{}{"server": "operator-server"},
		Options:   options,
	}

	data := map[string]interface{}{
		"BaseURL":    "https://acme.test",
		"body":       "<html>attacker controlled</html>",
		"server":     "nginx",
		"cli_role":   "from-response",
		"csrf_token": "extracted-from-response",
	}

	values := LLMPromptValues(executerOpts, data)
	require.Equal(t, "operator-body", values["body"], "a declared name must not take the response body")
	require.Equal(t, "operator-server", values["server"], "a declared name must not take a response header")
	require.Equal(t, "from-var", values["cli_role"], "a -var name must not take an extracted field")
	require.Equal(t, "auditor for https://acme.test", values["role"], "declared strings still resolve against the target")
	require.NotContains(t, values, "csrf_token")
}

func TestResolveLLMInputs(t *testing.T) {
	data := map[string]interface{}{
		"body_1": "user found",
		"body_2": "user not found",
	}

	resolved, ok := ResolveLLMInputs([]string{"{{body_1}}", "{{body_2}}"}, data)
	require.True(t, ok)
	require.Equal(t, []string{"user found", "user not found"}, resolved, "responses are resolved from the runtime values")

	// before the last response the later values do not exist yet, and asking
	// the model about a literal placeholder would waste a call
	_, ok = ResolveLLMInputs([]string{"{{body_1}}", "{{body_2}}"}, map[string]interface{}{"body_1": "only one"})
	require.False(t, ok)

	// a page that contains template-like text is still a resolved response
	withMarkers := map[string]interface{}{
		"body_1": "hello {{user}}",
		"body_2": "no such user",
		"user":   "must-not-leak",
	}
	resolved, ok = ResolveLLMInputs([]string{"{{body_1}}", "{{body_2}}"}, withMarkers)
	require.True(t, ok)
	require.Equal(t, []string{"hello {{user}}", "no such user"}, resolved, "body text stays opaque")

	withSection := map[string]interface{}{
		"body_1":   "token §Hostname§ here",
		"body_2":   "other",
		"Hostname": "must-not-leak",
	}
	resolved, ok = ResolveLLMInputs([]string{"{{body_1}}", "{{body_2}}"}, withSection)
	require.True(t, ok)
	require.Equal(t, []string{"token §Hostname§ here", "other"}, resolved)

	nilInputs, ok := ResolveLLMInputs(nil, data)
	require.True(t, ok)
	require.Nil(t, nilInputs)
}

type stubLLM struct {
	answer string
	calls  int
	prompt string
}

func (s *stubLLM) Complete(_ context.Context, prompt string, _ bool) (string, error) {
	s.calls++
	s.prompt = prompt
	return s.answer, nil
}

// The shared match func is what ssl, websocket, whois, code and javascript
// delegate to, so covering it covers all five.
func TestSharedMatchFuncEvaluatesLLMMatcher(t *testing.T) {
	stub := &stubLLM{answer: `{"verdict":"yes","confidence":0.94,"evidence":"stack trace"}`}
	matcher := &matchers.Matcher{
		Type:   matchers.MatcherTypeHolder{MatcherType: matchers.LLMMatcher},
		Prompt: "does this response leak a stack trace?",
	}
	matcher.SetLLMClient(stub)

	executerOpts := &ExecutorOptions{Options: &types.Options{Vars: goflags.RuntimeMap{}}}
	data := map[string]interface{}{"response": "PHP Warning: include() failed in /var/www/app.php"}

	isMatch, snippets := MakeDefaultMatchFuncWithExecutorOptions(data, matcher, executerOpts)
	require.True(t, isMatch)
	require.Equal(t, []string{"stack trace"}, snippets)
	require.Equal(t, 1, stub.calls)
	require.Contains(t, stub.prompt, "PHP Warning", "the response is framed into the prompt as the corpus")
}

func TestSharedExtractFuncEvaluatesLLMExtractor(t *testing.T) {
	stub := &stubLLM{answer: `{"version":"4.2.1"}`}
	extractor := &extractors.Extractor{
		Type:   extractors.ExtractorTypeHolder{ExtractorType: extractors.LLMExtractor},
		Prompt: "which version is reported?",
		Schema: map[string]string{"version": "string"},
	}
	extractor.SetLLMClient(stub)

	executerOpts := &ExecutorOptions{Options: &types.Options{Vars: goflags.RuntimeMap{}}}
	data := map[string]interface{}{"response": "Server: nginx 4.2.1"}

	require.Equal(t, map[string]struct{}{"4.2.1": {}}, MakeDefaultExtractFuncWithExecutorOptions(data, extractor, executerOpts))
	require.Equal(t, 1, stub.calls)
}

// Without a client an llm operator returns a negative result rather than an
// error, which is why every protocol must bind one at compile time.
func TestBindLLMOperatorsInjectsTheClient(t *testing.T) {
	matcher := &matchers.Matcher{Type: matchers.MatcherTypeHolder{MatcherType: matchers.LLMMatcher}, Prompt: "p"}
	extractor := &extractors.Extractor{Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.LLMExtractor}, Prompt: "p"}
	compiled := &operators.Operators{Matchers: []*matchers.Matcher{matcher}, Extractors: []*extractors.Extractor{extractor}}

	data := map[string]interface{}{"response": "anything"}
	isMatch, _ := MakeDefaultMatchFuncWithExecutorOptions(data, matcher, &ExecutorOptions{})
	require.False(t, isMatch, "an unbound llm matcher cannot match")

	stub := &stubLLM{answer: `{"verdict":"yes","confidence":0.9}`}
	require.True(t, BindLLMOperators(compiled, &ExecutorOptions{LLMClient: stub}))

	isMatch, _ = MakeDefaultMatchFuncWithExecutorOptions(data, matcher, &ExecutorOptions{})
	require.True(t, isMatch, "binding is what makes it evaluate")
}

func TestBindLLMOperatorsReportsNoneForNonLLMOperators(t *testing.T) {
	compiled := &operators.Operators{
		Matchers: []*matchers.Matcher{{Type: matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher}}},
	}
	require.False(t, BindLLMOperators(compiled, &ExecutorOptions{}))
	require.False(t, BindLLMOperators(nil, &ExecutorOptions{}))
}
