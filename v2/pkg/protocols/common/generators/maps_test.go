package generators

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMergeMapsMany(t *testing.T) {
	got := MergeMapsMany(map[string]interface{}{"a": []string{"1", "2"}, "c": "5"}, map[string][]string{"b": []string{"3", "4"}})
	require.Equal(t, map[string][]string{
		"a": []string{"1", "2"},
		"b": []string{"3", "4"},
		"c": []string{"5"},
	}, got, "could not get correct merged map")
}
