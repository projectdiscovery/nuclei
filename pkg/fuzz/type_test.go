package fuzz

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils/yaml"
	"github.com/stretchr/testify/require"
)

func TestSliceOrMapSliceUnmarshalYAMLSequence(t *testing.T) {
	var value SliceOrMapSlice

	err := yaml.Unmarshal([]byte("- first\n- second\n"), &value)
	require.NoError(t, err)
	require.Equal(t, []string{"first", "second"}, value.Value)
	require.Nil(t, value.KV)
}

func TestSliceOrMapSliceUnmarshalYAMLMapPreservesOrder(t *testing.T) {
	var value SliceOrMapSlice

	err := yaml.Unmarshal([]byte("first: one\nsecond: two\nthird: three\n"), &value)
	require.NoError(t, err)
	require.NotNil(t, value.KV)

	keys := make([]string, 0, 3)
	values := make([]string, 0, 3)
	value.KV.Iterate(func(key, value string) bool {
		keys = append(keys, key)
		values = append(values, value)
		return true
	})

	require.Equal(t, []string{"first", "second", "third"}, keys)
	require.Equal(t, []string{"one", "two", "three"}, values)
}

func TestSliceOrMapSliceUnmarshalYAMLNonStringEntries(t *testing.T) {
	for _, data := range []string{"a: 1\n", "1: x\n", "a: [x]\n", "a: true\n"} {
		var value SliceOrMapSlice
		require.NotPanics(t, func() {
			err := yaml.Unmarshal([]byte(data), &value)
			require.Error(t, err, "non-string entry should be rejected: %q", data)
			require.Contains(t, err.Error(), "must be strings")
		})
		require.Nil(t, value.KV)
	}

	// quoted values are strings and keep working
	var value SliceOrMapSlice
	require.NoError(t, yaml.Unmarshal([]byte("a: \"1\"\n\"2\": b\n"), &value))
	require.NotNil(t, value.KV)
}
