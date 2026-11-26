package compiler

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// A Set that contains itself used to overflow the Go stack on export and kill the process.
func TestExecuteSelfReferencingSetResult(t *testing.T) {
	result, err := executeScript(t, t.Name(), false, `var s = new Set(); s.add(s); s`)
	require.NoError(t, err)
	require.NotNil(t, result["response"])
}

// Deeply nested source used to overflow the Go stack in the parser.
func TestCompileDeepNesting(t *testing.T) {
	const n = 1000000
	_, err := SourceAutoMode(strings.Repeat("(", n)+"a"+strings.Repeat(")", n), false)
	require.ErrorContains(t, err, "Maximum nesting depth exceeded")
}

// A context-first Go function called with fewer arguments used to panic in reflect.
// The missing port must reach GetServerInfo as 0, so its dial error names 127.0.0.1:0.
func TestContextFunctionMissingArguments(t *testing.T) {
	result, err := executeScript(t, t.Name(), false, `require("nuclei/redis").GetServerInfo("127.0.0.1")`)
	require.ErrorContains(t, err, "127.0.0.1:0")
	errText, _ := result["error"].(string)
	require.Contains(t, errText, "127.0.0.1:0")
	require.NotContains(t, errText, "reflect")
	require.NotContains(t, errText, "panic")
}
