package expressions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEvaluate(t *testing.T) {
	items := []struct {
		input    string
		expected string
		extra    map[string]interface{}
	}{
		{input: "{{hex_encode('PING')}}", expected: "50494e47", extra: map[string]interface{}{}},
		{input: "test", expected: "test", extra: map[string]interface{}{}},
		{input: "{{hex_encode(Item)}}", expected: "50494e47", extra: map[string]interface{}{"Item": "PING"}},
		{input: "{{hex_encode(Item)}}\r\n", expected: "50494e47\r\n", extra: map[string]interface{}{"Item": "PING"}},
	}
	for _, item := range items {
		value, err := Evaluate(item.input, item.extra)
		require.Nil(t, err, "could not evaluate helper")

		require.Equal(t, item.expected, value, "could not get correct expression")
	}
}
