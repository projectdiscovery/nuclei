package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
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
