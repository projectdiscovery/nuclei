package multiproto

import (
	"testing"

	"github.com/projectdiscovery/goflags"
	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/variables"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
)

func TestCompileStoresDataOnlyReadOnlyArgs(t *testing.T) {
	optionVars := goflags.RuntimeMap{}
	require.NoError(t, optionVars.Set("option_key=option-value"))

	templateVars := variables.Variable{
		InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(2),
	}
	templateVars.Set("template_key", "{{constant_key}}-{{option_key}}")
	templateVars.Set("shadowed", "template-value")

	executerOptions := &protocols.ExecutorOptions{
		Options: &types.Options{
			Vars: optionVars,
		},
		Constants: map[string]interface{}{
			"constant_key": "constant-value",
			"shadowed":     "constant-shadow",
		},
		Variables: templateVars,
	}

	m := NewMultiProtocol(nil, executerOptions, nil)

	require.NoError(t, m.Compile())
	require.Equal(t, "constant-value", m.readOnlyArgs["constant_key"])
	require.Equal(t, "option-value", m.readOnlyArgs["option_key"])
	require.Equal(t, "constant-shadow", m.readOnlyArgs["shadowed"])
	require.Equal(t, "constant-value-option-value", m.readOnlyArgs["template_key"])
	require.Equal(t, map[string]interface{}{
		"template_key": "constant-value-option-value",
	}, m.readOnlyVars)
}
