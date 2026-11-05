package expressions

import (
	"errors"
	"testing"

	"github.com/projectdiscovery/govaluate"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
	"github.com/stretchr/testify/require"
)

func withTestHelperFunction(t *testing.T, name string, fn govaluate.ExpressionFunction) {
	t.Helper()

	originalFn, hadFn := dsl.HelperFunctions[name]
	dsl.HelperFunctions[name] = fn

	t.Cleanup(func() {
		if hadFn {
			dsl.HelperFunctions[name] = originalFn
			return
		}
		delete(dsl.HelperFunctions, name)
	})
}

func TestUnresolvedVariablesCheck(t *testing.T) {
	tests := []struct {
		data string
		err  error
	}{
		{"{{test}}", errors.New("unresolved variables found: test")},
		{"{{test}}/{{another}}", errors.New("unresolved variables found: test,another")},
		{"test", nil},
		{"%7b%7btest%7d%7d", errors.New("unresolved variables found: test")},
		{"%7B%7Bfirst%2Asecond%7D%7D", errors.New("unresolved variables found: first%2Asecond")},
		{"{{7*7}}", nil},
		{"{{'a'+'b'}}", nil},
		{"{{'a'}}", nil},
	}
	for _, test := range tests {
		err := ContainsUnresolvedVariables(test.data)
		require.Equal(t, test.err, err, "could not get unresolved variables")
	}
}

func TestReferencesVariables(t *testing.T) {
	names := map[string]interface{}{"Hostname": "", "Port": ""}

	tests := []struct {
		data string
		want bool
	}{
		{data: "user@{{Hostname}}", want: true},
		{data: "{{to_lower(Hostname)}}:{{Port}}", want: true},
		{data: "{{Hostname_suffix}}", want: false},
		{data: "{{secret}}-{{to_upper(seed)}}", want: false},
		{data: "{{7*7}}", want: false},
		{data: "Hostname", want: false},
	}

	for _, test := range tests {
		require.Equal(t, test.want, ReferencesVariables(test.data, names), test.data)
	}
}

func TestUnresolvedVariablesCheckDoesNotExecuteHelpers(t *testing.T) {
	var calls int
	withTestHelperFunction(t, "test_side_effect", func(args ...interface{}) (interface{}, error) {
		calls++
		return "ok", nil
	})

	err := ContainsUnresolvedVariables("{{test_side_effect(1)}}")
	require.NoError(t, err)
	require.Zero(t, calls)
}
