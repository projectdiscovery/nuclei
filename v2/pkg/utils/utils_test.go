package utils

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIsEmpty(t *testing.T) {
	testCases := [...][2]interface{}{
		{"", true},
		{' ', true},
		{'\t', true},
		{'\n', true},
		{" ", true},
		{"\n", true},
		{"\t", true},
		{0, true},
		{[]string{}, true},
		{[0]string{}, true},
		{[...]string{}, true},
		{[]int{}, true},
		{[0]int{}, true},
		{[...]int{}, true},
		{interface{}(nil), true},
		{[]struct{}(nil), true},
		{[]interface{}(nil), true},
		{map[string]interface{}{}, true},
		{nil, true},

		{'a', false},
		{1, false},
		{3.14, false},
		{" test ", false},
		{[]string{"a"}, false},
		{[...]string{"a"}, false},
		{[2]string{"a", "b"}, false},
		{[]int{1, 2}, false},
		{[...]int{1, 2}, false},
		{struct{ a string }{"a"}, false},
		{&struct{ a string }{"a"}, false},
		{[]struct{ a string }{{"b"}, {"b"}}, false},
		{map[string]interface{}{"a": 13}, false},
	}

	for index, testCase := range testCases {
		t.Run(fmt.Sprintf("%v # %d", testCase[0], index), func(t *testing.T) {
			assert.Equal(t, testCase[1], IsEmpty(testCase[0]))
		})
	}
}

func TestVariadicIsEmpty(t *testing.T) {
	testVariadicIsEmpty := func(expected bool, value ...interface{}) {
		t.Run(fmt.Sprintf("%v", value), func(testCase *testing.T) {
			assert.Equal(testCase, expected, IsEmpty(value...))
		})
	}

	testVariadicIsEmpty(false, [2]int{1, 2}, [0]int{})
	testVariadicIsEmpty(false, [0]int{}, [2]int{1, 2})
	testVariadicIsEmpty(false, [0]int{}, " abc ")
	testVariadicIsEmpty(false, [0]int{}, []string{}, 123)
	testVariadicIsEmpty(false, [0]int{}, []string{}, []string{"a"})
	testVariadicIsEmpty(false, [0]int{}, map[string]int{"a": 123}, map[string]interface{}{"b": "c"})

	testVariadicIsEmpty(true, [0]int{}, "")
	testVariadicIsEmpty(true, [0]int{}, []string{})
	testVariadicIsEmpty(true, [0]int{}, []string{}, 0)
}
