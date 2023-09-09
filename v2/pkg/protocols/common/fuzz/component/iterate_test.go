package component

import (
	"encoding/json"
	"fmt"
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

	marshalled, _ := json.MarshalIndent(flattened, "", "  ")
	fmt.Println(string(marshalled))

	nested, err := flat.Unflatten(flattened, opts)
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, data, nested, "unexpected data")
}
