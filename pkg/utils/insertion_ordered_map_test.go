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
	var data = `200: ok
true: yes
1.5: half
name: value`

	var value InsertionOrderedStringMap
	err := yaml.Unmarshal([]byte(data), &value)
	require.NoError(t, err, "could not unmarshal map")

	var items []string
	value.ForEach(func(key string, value interface{}) {
		items = append(items, key+"="+value.(string))
	})
	require.Equal(t, []string{"200=ok", "true=yes", "1.5=half", "name=value"}, items)
}

func TestUnmarshalInsertionOrderedMapYAMLTwice(t *testing.T) {
	var value InsertionOrderedStringMap
	require.NoError(t, yaml.Unmarshal([]byte("a1: one\na2: two"), &value))
	require.NoError(t, yaml.Unmarshal([]byte("b1: three"), &value))

	var items []string
	value.ForEach(func(key string, value interface{}) {
		items = append(items, key)
	})
	require.Equal(t, []string{"b1"}, items)
	require.Equal(t, 1, value.Len())
}
