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

func Test_JSONValues(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		modified string
	}{
		{
			name:     "object",
			data:     `{"foo":"bar"}`,
			modified: `{"foo":"mutation"}`,
		},
		{
			name:     "array",
			data:     `{"foo":["bar","baz"]}`,
			modified: `{"foo":["bar","baz","mutation"]}`,
		},
		{
			name:     "nested",
			data:     `{"foo":{"bar":"baz"}}`,
			modified: `{"foo":{"bar":"mutation"}}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := NewValue(test.data)

			encoded, err := value.Encode()
			require.NoError(t, err, "could not encode value")
			require.Equal(t, test.data, encoded, "unexpected encoded string")

			for k := range value.Parsed() {
				set := value.SetParsedValue(k, "mutation")
				require.True(t, set, "could not set parsed value")

				encoded, err := value.Encode()
				require.NoError(t, err, "could not encode value")

				require.Equal(t, test.modified, encoded, "unexpected encoded string")
			}
		})
	}
}
