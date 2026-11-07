package fuzz

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/component"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/variables"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

const (
	// requestBodyWithDSL is request data that looks like a DSL expression.
	requestBodyWithDSL = `PLAIN-{{to_upper("abc")}}-END`
	queryRuleTarget    = "http://127.0.0.1/echo?p=SEED"
)

// fakeInteractshClient hands out numbered URLs without contacting a server.
// Fuzz rules only allocate URLs through NewURLWithData, so the embedded nil
// IClient is never called.
type fakeInteractshClient struct {
	interactsh.IClient

	issued int
}

func (c *fakeInteractshClient) NewURLWithData(string) (string, error) {
	c.issued++

	return fmt.Sprintf("oast%d.example", c.issued), nil
}

// newQueryRule compiles a single-mode rule that replaces the p query value
// with fuzzValue.
func newQueryRule(
	t *testing.T,
	fuzzValue string,
	generator *generators.PayloadGenerator,
	templateVars variables.Variable,
	client interactsh.IClient,
) *Rule {
	t.Helper()

	rule := &Rule{
		Part: component.RequestQueryComponent,
		Type: "replace",
		Mode: "single",
		Fuzz: SliceOrMapSlice{Value: []string{fuzzValue}},
	}
	err := rule.Compile(generator, &protocols.ExecutorOptions{
		Variables:  templateVars,
		Options:    &types.Options{},
		Interactsh: client,
	})
	require.NoError(t, err)

	return rule
}

// executeQueryRule runs rule against queryRuleTarget and returns the generated
// requests.
func executeQueryRule(
	t *testing.T,
	rule *Rule,
	method string,
	body io.Reader,
	values map[string]any,
) []GeneratedRequest {
	t.Helper()

	req, err := retryablehttp.NewRequest(method, queryRuleTarget, body)
	require.NoError(t, err)

	var got []GeneratedRequest
	err = rule.Execute(&ExecuteRuleInput{
		Input:       contextargs.NewWithInput(context.Background(), queryRuleTarget),
		BaseRequest: req,
		Values:      values,
		Callback: func(gr GeneratedRequest) bool {
			got = append(got, gr)

			return true
		},
	})
	require.NoError(t, err)

	return got
}

// newRequestDataVariableRule returns a query rule whose template declares
// b: "{{body}}", so b captures request data.
func newRequestDataVariableRule(t *testing.T, fuzzValue string, payloads map[string]any) *Rule {
	t.Helper()

	templateVars := newFuzzTestVariables()
	templateVars.Set("b", "{{body}}")

	var generator *generators.PayloadGenerator

	if payloads != nil {
		var err error

		generator, err = generators.New(
			payloads, generators.BatteringRamAttack, "", disk.NewCatalog(""), "", types.DefaultOptions(),
		)
		require.NoError(t, err)
	}

	// The CLI creates an Interactsh client even with -no-interactsh.
	return newQueryRule(t, fuzzValue, generator, templateVars, &interactsh.Client{})
}

// fuzzedQueryValues runs rule against a POST request whose body is
// requestBodyWithDSL and returns the fuzzed p query value of each generated
// request.
func fuzzedQueryValues(t *testing.T, rule *Rule) []string {
	t.Helper()

	generated := executeQueryRule(t, rule, http.MethodPost, strings.NewReader(requestBodyWithDSL), map[string]any{
		"body": requestBodyWithDSL,
	})

	got := make([]string, 0, len(generated))
	for _, gr := range generated {
		got = append(got, gr.Request.URL.Query().Get("p"))
	}

	return got
}

func TestExecuteKeepsRequestDataInTemplateVariableLiteral(t *testing.T) {
	t.Parallel()

	t.Run("fuzz value", func(t *testing.T) {
		t.Parallel()

		rule := newRequestDataVariableRule(t, "{{b}}", nil)

		require.Equal(t, []string{requestBodyWithDSL}, fuzzedQueryValues(t, rule))
	})

	t.Run("payload value", func(t *testing.T) {
		t.Parallel()

		rule := newRequestDataVariableRule(t, "{{inj}}", map[string]any{
			"inj": []any{"{{b}}"},
		})

		// Each run iterates a fresh value map. Repeat so the result
		// cannot depend on map iteration order.
		for range 256 {
			require.Equal(t, []string{requestBodyWithDSL}, fuzzedQueryValues(t, rule))
		}
	})
}

func TestExecuteRendersTemplateVariableInteractshMarker(t *testing.T) {
	t.Parallel()

	templateVars := newFuzzTestVariables()
	templateVars.Set("marker", "{{interactsh-url}}")
	rule := newQueryRule(t, "{{marker}}", nil, templateVars, &fakeInteractshClient{})

	got := executeQueryRule(t, rule, http.MethodGet, nil, nil)

	require.Len(t, got, 1)
	require.Equal(t, []string{"oast1.example"}, got[0].InteractURLs)
	require.Equal(t, "oast1.example", got[0].Request.URL.Query().Get("p"))
}

func TestPrepareGeneratorValuesRendersPayloadSharingVariableName(t *testing.T) {
	t.Parallel()

	templateVars := newFuzzTestVariables()
	templateVars.Set("inj", "variable")

	rule := &Rule{
		options: &protocols.ExecutorOptions{
			Variables:  templateVars,
			Options:    &types.Options{},
			Interactsh: &fakeInteractshClient{},
		},
	}

	values, _ := rule.prepareGeneratorValues(map[string]any{
		"inj": `{{to_upper("payload")}}`,
	}, nil)

	require.Equal(t, "PAYLOAD", values["inj"])
}

func TestPrepareGeneratorValuesRendersPayloadsAgainstUnrenderedInput(t *testing.T) {
	t.Parallel()

	rule := &Rule{
		options: &protocols.ExecutorOptions{
			Variables:  newFuzzTestVariables(),
			Options:    &types.Options{},
			Interactsh: &interactsh.Client{},
		},
	}

	for range 256 {
		values, _ := rule.prepareGeneratorValues(map[string]any{
			"upper": `{{to_upper("x")}}`,
			"ref":   "{{upper}}",
		}, nil)

		require.Equal(t, "X", values["upper"])
		// ref sees the unrendered definition of upper as data.
		require.Equal(t, `{{to_upper("x")}}`, values["ref"])
	}
}
