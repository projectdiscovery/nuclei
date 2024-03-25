package component

import (
	"testing"

	"github.com/leslie-qiwa/flat"
	"github.com/stretchr/testify/require"
)

func TestFlatMap_FlattenUnflatten(t *testing.T) {
	data := map[string]interface{}{
		"foo": "bar",
		"bar": map[string]interface{}{
			"baz": "foo",
		},
		"slice": []interface{}{
			"foo",
			"bar",
		},
		"with.dot": map[string]interface{}{
			"foo": "bar",
		},
	}

	opts := &flat.Options{
		Safe:      true,
		Delimiter: "~",
	}
	flattened, err := flat.Flatten(data, opts)
	if err != nil {
		t.Fatal(err)
	}

	nested, err := flat.Unflatten(flattened, opts)
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, data, nested, "unexpected data")
}

func TestAnySlice(t *testing.T) {
	data := []any{}
	data = append(data, []int{1, 2, 3})
	data = append(data, []string{"foo", "bar"})
	data = append(data, []bool{true, false})
	data = append(data, []float64{1.1, 2.2, 3.3})

	for _, d := range data {
		val, ok := IsTypedSlice(d)
		require.True(t, ok, "expected slice")
		require.True(t, val != nil, "expected value but got nil")
	}
}
