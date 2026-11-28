package utils

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils/yaml"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalInsertionOrderedMapYAML(t *testing.T) {
	var data = `a1: test
a2: value
a3: new`

	var value InsertionOrderedStringMap
	err := yaml.Unmarshal([]byte(data), &value)
	require.NoError(t, err, "could not unmarshal map")

	var items []string
	value.ForEach(func(key string, value interface{}) {
		items = append(items, key)
	})
	require.Equal(t, []string{"a1", "a2", "a3"}, items, "could not get ordered keys")
}

func TestUnmarshalInsertionOrderedMapYAMLNonStringKeys(t *testing.T) {
	for _, data := range []string{"1: one\nfoo: bar", "true: one", "1.5: one"} {
		var value InsertionOrderedStringMap
		require.NotPanics(t, func() {
			err := yaml.Unmarshal([]byte(data), &value)
			require.Error(t, err, "non-string key should be rejected: %q", data)
			require.Contains(t, err.Error(), "keys must be strings")
		})
	}

	// quoted keys are strings and keep working
	var value InsertionOrderedStringMap
	require.NoError(t, yaml.Unmarshal([]byte("\"1\": one\nfoo: bar"), &value))
	var keys []string
	value.ForEach(func(key string, _ interface{}) {
		keys = append(keys, key)
	})
	require.Equal(t, []string{"1", "foo"}, keys)
}
