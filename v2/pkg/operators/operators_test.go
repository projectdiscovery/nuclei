package operators

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMakeDynamicValuesCallback(t *testing.T) {
	input := map[string][]string{
		"a": []string{"1", "2"},
		"b": []string{"3"},
		"c": []string{},
		"d": []string{"A", "B", "C"},
	}

	count := 0
	MakeDynamicValuesCallback(input, true, func(data map[string]interface{}) bool {
		count++
		require.Len(t, data, 3, "could not get correct output length")
		return false
	})
	require.Equal(t, 3, count, "could not get correct result count")

	t.Run("all", func(t *testing.T) {
		input := map[string][]string{
			"a": []string{"1"},
			"b": []string{"2"},
			"c": []string{"3"},
		}

		count := 0
		MakeDynamicValuesCallback(input, true, func(data map[string]interface{}) bool {
			count++
			require.Len(t, data, 3, "could not get correct output length")
			return false
		})
		require.Equal(t, 1, count, "could not get correct result count")
	})

	t.Run("first", func(t *testing.T) {
		input := map[string][]string{
			"a": []string{"1", "2"},
			"b": []string{"3"},
			"c": []string{},
			"d": []string{"A", "B", "C"},
		}

		count := 0
		MakeDynamicValuesCallback(input, false, func(data map[string]interface{}) bool {
			count++
			require.Len(t, data, 3, "could not get correct output length")
			return false
		})
		require.Equal(t, 1, count, "could not get correct result count")
	})
}
