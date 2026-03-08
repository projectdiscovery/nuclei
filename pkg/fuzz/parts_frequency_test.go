package fuzz

import (
	"net/http"
	"testing"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/frequency"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/variables"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestExecWithInputUsesActualParameterForFrequency(t *testing.T) {
	rule := &Rule{Part: "path", Type: "replace", Mode: "single"}

	options := &types.Options{}
	options.Vars = goflags.RuntimeMap{}

	rule.options = &protocols.ExecutorOptions{
		TemplateID:          "test-template",
		Options:             options,
		Variables:           variables.Variable{InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(0)},
		Constants:           map[string]interface{}{},
		FuzzParamsFrequency: frequency.New(100, 1),
		Progress:            &testutils.MockProgressClient{},
	}

	// Mark a different numeric path segment as frequent on the same target.
	// With the old code, both values collided on the raw index key "2".
	targetReq, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/blog/99/post", nil)
	require.NoError(t, err)
	rule.options.FuzzParamsFrequency.MarkParameter("99", targetReq.String(), rule.options.TemplateID)

	baseReq, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/user/55/profile", nil)
	require.NoError(t, err)

	input := &ExecuteRuleInput{
		Input:       &contextargs.Context{},
		BaseRequest: baseReq,
		Values:      map[string]interface{}{},
	}

	called := false
	input.Callback = func(gr GeneratedRequest) bool {
		called = true
		require.Equal(t, "55", gr.Parameter)
		return true
	}

	err = rule.execWithInput(input, baseReq, nil, nil, "2", "55", "", "", "", "")
	require.NoError(t, err)
	require.True(t, called, "expected callback to run; frequency tracking should key by actual path value, not index")
}
