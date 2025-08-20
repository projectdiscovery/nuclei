package dataformat

import (
	"testing"

	mapsutil "github.com/projectdiscovery/utils/maps"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultiPartFormEncode(t *testing.T) {
	tests := []struct {
		name     string
		fields   map[string]any
		wantErr  bool
		contains []string // strings that should appear in encoded output
	}{
		{
			name: "duplicate fields ([]string) - checkbox scenario",
			fields: map[string]any{
				"interests": []string{"sports", "music", "reading"},
				"colors":    []string{"red", "blue"},
			},
			contains: []string{"interests", "sports", "music", "reading", "colors", "red", "blue"},
		},
		{
			name: "single string fields - backward compatibility",
			fields: map[string]any{
				"username": "john",
				"email":    "john@example.com",
			},
			contains: []string{"username", "john", "email", "john@example.com"},
		},
		{
			name: "mixed types",
			fields: map[string]any{
				"string": "text",
				"array":  []string{"item1", "item2"},
				"number": 42, // tests fmt.Sprint fallback
			},
			contains: []string{"string", "text", "array", "item1", "item2", "number", "42"},
		},
		{
			name: "empty array - should not appear in output",
			fields: map[string]any{
				"emptyArray":  []string{},
				"normalField": "value",
			},
			contains: []string{"normalField", "value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Test panicked: %v", r)
				}
			}()

			form := NewMultiPartForm()
			form.boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"

			kv := mapsutil.NewOrderedMap[string, any]()
			for k, v := range tt.fields {
				kv.Set(k, v)
			}

			encoded, err := form.Encode(KVOrderedMap(&kv))

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			for _, expected := range tt.contains {
				assert.Contains(t, encoded, expected)
			}

			t.Logf("Encoded output:\n%s", encoded)
		})
	}
}

func TestMultiPartFormRoundTrip(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Test panicked: %v", r)
		}
	}()

	form := NewMultiPartForm()
	form.boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"

	original := mapsutil.NewOrderedMap[string, any]()
	original.Set("username", "john")
	original.Set("interests", []string{"sports", "music", "reading"})

	encoded, err := form.Encode(KVOrderedMap(&original))
	require.NoError(t, err)

	decoded, err := form.Decode(encoded)
	require.NoError(t, err)

	assert.Equal(t, "john", decoded.Get("username"))
	assert.ElementsMatch(t, []string{"sports", "music", "reading"}, decoded.Get("interests"))

	t.Logf("Encoded output:\n%s", encoded)
}
